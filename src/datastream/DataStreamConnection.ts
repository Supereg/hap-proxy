import {EventEmitter, EventMap} from "../lib/EventEmitter";
import {Socket} from "net";
import {DataStreamMessage, DataStreamParser, DataStreamReader, DataStreamWriter, HDSFrame, MessageType} from "./index";
import * as encryption from "../crypto/encryption";
import assert from 'assert';
import createDebug from "debug";

const debug = createDebug('DataStream:Connection');

export enum ConnectionState {
    UNINITIALIZED, // encryption/decryption keys not present
    READY = 1,
    CLOSING,
    CLOSED,
}

export enum DataStreamConnectionEvents {
    PAYLOAD = "raw-payload",
    MESSAGE = "message",
    CLOSED = "closed",
}

export interface DataStreamConnectionEventMap extends EventMap {
    [DataStreamConnectionEvents.PAYLOAD]: (payload: Buffer) => void;
    [DataStreamConnectionEvents.MESSAGE]: (message: DataStreamMessage) => void;
    [DataStreamConnectionEvents.CLOSED]: () => void;
}

export abstract class DataStreamConnection<E extends DataStreamConnectionEventMap> extends EventEmitter<E> {

    private static readonly MAX_PAYLOAD_LENGTH = 0x11111111111111111111;

    protected readonly socket: Socket;
    remoteAddress: string = "";
    protected state: ConnectionState = ConnectionState.UNINITIALIZED;
    protected connected: boolean = false;

    private encryptionKey?: Buffer;
    private decryptionKey?: Buffer;

    private encryptionNonce: number;
    private readonly encryptionNonceBuffer: Buffer;
    private decryptionNonce: number;
    private readonly decryptionNonceBuffer: Buffer;

    private frameBuffer?: Buffer; // used to store incomplete HDS frames

    protected constructor(socket: Socket) {
        super();
        this.socket = socket;

        this.socket.setNoDelay(true); // disable Nagle algorithm
        this.socket.setKeepAlive(true);

        this.encryptionNonce = 0;
        this.encryptionNonceBuffer = Buffer.alloc(8);
        this.decryptionNonce = 0;
        this.decryptionNonceBuffer = Buffer.alloc(8);

        this.socket.on('data', this.handleData.bind(this));
        this.socket.on('error', this.handleError.bind(this));
        this.socket.on('close', this.handleClose.bind(this)); // we MUST register for this event, otherwise the error will bubble up to the top and crash the node process entirely.
    }

    protected setKeys(encryptionKey: Buffer, decryptionKey: Buffer) {
        assert(this.state === ConnectionState.UNINITIALIZED);

        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
        this.state = ConnectionState.READY;
    }

    protected handleInitialization(firstFrame: HDSFrame) {
        throw new Error("Unsupported operation!");
    }

    protected handleData(data: Buffer) {
        if (this.state >= ConnectionState.CLOSING) {
            return;
        }

        let frameIndex = 0;
        const frames: HDSFrame[] = this.decodeHDSFrames(data);
        if (frames.length === 0) { // not enough data
            return;
        }

        if (this.state === ConnectionState.UNINITIALIZED) { // really only relevant for the server side
            // at the beginning we are only interested in trying to decrypt the first frame in order to test decryption keys
            const firstFrame = frames[frameIndex++];
            this.handleInitialization(firstFrame);

            if (this.state === ConnectionState.UNINITIALIZED) {
                // did not find a prepared session, server already closed this connection; nothing to do here
                return;
            }
        }

        for (; frameIndex < frames.length; frameIndex++) { // decrypt all remaining frames
            if (!this.decryptHDSFrame(frames[frameIndex])) {
                debug("[%s] HDS frame decryption or authentication failed. Connection will be terminated!", this.remoteAddress);
                this.close();
                return;
            }
        }

        frames.forEach(frame => this.emit(DataStreamConnectionEvents.PAYLOAD, frame.plaintextPayload));

        const messages: DataStreamMessage[] = this.decodePayloads(frames); // decode contents of payload
        messages.forEach(message => this.emit(DataStreamConnectionEvents.MESSAGE, message));
    }

    protected decodeHDSFrames(data: Buffer) {
        if (this.frameBuffer !== undefined) {
            data = Buffer.concat([this.frameBuffer, data]);
            this.frameBuffer = undefined;
        }

        const totalBufferLength = data.length;
        const frames: HDSFrame[] = [];

        for (let frameBegin = 0; frameBegin < totalBufferLength;) {
            if (frameBegin + 4 > totalBufferLength) {
                // we don't have enough data in the buffer for the next header
                this.frameBuffer = data.slice(frameBegin);
                break;
            }

            const payloadType = data.readUInt8(frameBegin); // type defining structure of payload; 8-bit; currently expected to be 1
            const payloadLength = data.readUIntBE(frameBegin + 1, 3); // read 24-bit big-endian uint length field

            if (payloadLength > DataStreamConnection.MAX_PAYLOAD_LENGTH) {
                debug("[%s] Connection send payload with size bigger than the maximum allow for data stream", this.remoteAddress);
                this.close();
                return [];
            }

            const remainingBufferLength = totalBufferLength - frameBegin - 4; // subtract 4 for payloadType (1-byte) and payloadLength (3-byte)
            // check if the data from this frame is already there (payload + 16-byte authTag)
            if (payloadLength + 16 > remainingBufferLength) {
                // Frame is fragmented, so we wait until we receive more
                this.frameBuffer = data.slice(frameBegin);
                break;
            }

            const payloadBegin = frameBegin + 4;
            const authTagBegin = payloadBegin + payloadLength;

            const header = data.slice(frameBegin, payloadBegin); // header is also authenticated using authTag
            const cipheredPayload = data.slice(payloadBegin, authTagBegin);
            const plaintextPayload = Buffer.alloc(payloadLength);
            const authTag = data.slice(authTagBegin, authTagBegin + 16);

            frameBegin = authTagBegin + 16; // move to next frame

            if (payloadType === 1) {
                const hdsFrame: HDSFrame = {
                    header: header,
                    cipheredPayload: cipheredPayload,
                    plaintextPayload: plaintextPayload,
                    authTag: authTag,
                };
                frames.push(hdsFrame);
            } else {
                debug("[%s] Encountered unknown payload type %d for payload: %s", this.remoteAddress, plaintextPayload.toString('hex'));
            }
        }

        return frames;
    }

    decryptHDSFrame(frame: HDSFrame, keyOverwrite?: Buffer): boolean {
        encryption.writeUInt64LE(this.decryptionNonce, this.decryptionNonceBuffer, 0); // update nonce buffer

        const key = keyOverwrite || this.decryptionKey!;
        if (encryption.verifyAndDecrypt(key, this.decryptionNonceBuffer,
            frame.cipheredPayload, frame.authTag, frame.header, frame.plaintextPayload)) {
            this.decryptionNonce++; // we had a successful encryption, increment the nonce
            return true;
        } else {
            // frame decryption or authentication failed. Could happen when our guess for a PreparedDataStreamSession is wrong
            return false;
        }
    }

    protected decodePayloads(frames: HDSFrame[]) {
        const messages: DataStreamMessage[] = [];

        frames.forEach(frame => {
            const payload = frame.plaintextPayload;

            const headerLength = payload.readUInt8(0);
            const messageLength = payload.length - headerLength - 1;

            const headerBegin = 1;
            const messageBegin = headerBegin + headerLength;

            const headerPayload = new DataStreamReader(payload.slice(headerBegin, headerBegin + headerLength));
            const messagePayload = new DataStreamReader(payload.slice(messageBegin, messageBegin + messageLength));

            let headerDictionary: Record<any, any>;
            let messageDictionary: Record<any, any>;
            try {
                headerDictionary = DataStreamParser.decode(headerPayload);
                headerPayload.finished();
            } catch (error) {
                debug("[%s] Failed to decode header payload: %s", this.remoteAddress, error.message);
                return;
            }

            try {
                messageDictionary = DataStreamParser.decode(messagePayload);
                messagePayload.finished();
            } catch (error) {
                debug("[%s] Failed to decode message payload: %s (header: %o)", this.remoteAddress, error.message, headerDictionary);
                return;
            }

            let type: MessageType;
            const protocol: string = headerDictionary["protocol"];
            let topic: string;
            let id: number | undefined = undefined;
            let status: number | undefined = undefined;

            if (headerDictionary["event"] !== undefined) {
                type = MessageType.EVENT;
                topic = headerDictionary["event"];
            } else if (headerDictionary["request"] !== undefined) {
                type = MessageType.REQUEST;
                topic = headerDictionary["request"];
                id = headerDictionary["id"];
            } else if (headerDictionary["response"] !== undefined) {
                type = MessageType.RESPONSE;
                topic = headerDictionary["response"];
                id = headerDictionary["id"];
                status = headerDictionary["status"];
            } else {
                debug("[%s] Encountered unknown payload header format: %o (message: %o)", this.remoteAddress, headerDictionary, messageDictionary);
                return;
            }

            const message = {
                type: type,
                protocol: protocol,
                topic: topic,
                id: id,
                status: status,
                message: messageDictionary,
            };
            messages.push(message);
        });

        return messages;
    }

    sendHDSFrame(header: Record<any, any>, message: Record<any, any>) {
        if (this.state >= ConnectionState.CLOSING) {
            throw Error("Cannot send message on closing/closed socket!");
        }

        const headerWriter = new DataStreamWriter();
        const messageWriter = new DataStreamWriter();

        DataStreamParser.encode(header, headerWriter);
        DataStreamParser.encode(message, messageWriter);


        const payloadHeaderBuffer = Buffer.alloc(1);
        payloadHeaderBuffer.writeUInt8(headerWriter.length(), 0);
        const payloadBuffer = Buffer.concat([payloadHeaderBuffer, headerWriter.getData(), messageWriter.getData()]);
        this.sendRawHDSFrame(payloadBuffer);
    }

    sendRawHDSFrame(payloadBuffer: Buffer) {
        // TODO buffer frames if !connected
        if (payloadBuffer.length > DataStreamConnection.MAX_PAYLOAD_LENGTH) {
            throw new Error("Tried sending payload with length larger than the maximum allowed for data stream");
        }

        const frameTypeBuffer = Buffer.alloc(1);
        frameTypeBuffer.writeUInt8(1, 0);
        let frameLengthBuffer = Buffer.alloc(4);
        frameLengthBuffer.writeUInt32BE(payloadBuffer.length, 0);
        frameLengthBuffer = frameLengthBuffer.slice(1, 4); // a bit hacky but the only real way to write 24-bit int in node

        const frameHeader = Buffer.concat([frameTypeBuffer, frameLengthBuffer]);
        const authTag = Buffer.alloc(16);
        const cipheredPayload = Buffer.alloc(payloadBuffer.length);

        encryption.writeUInt64LE(this.encryptionNonce++, this.encryptionNonceBuffer);
        encryption.encryptAndSeal(this.encryptionKey!, this.encryptionNonceBuffer, payloadBuffer, frameHeader, cipheredPayload, authTag);

        this.socket.write(Buffer.concat([frameHeader, cipheredPayload, authTag]));

        /* Useful for debugging outgoing packages and detecting encoding errors
        console.log("SENT DATA: " + payloadBuffer.toString("hex"));
        const frame: HDSFrame = {
            header: frameHeader,
            plaintextPayload: payloadBuffer,
            cipheredPayload: cipheredPayload,
            authTag: authTag,
        };
        const sentMessage = this.decodePayloads([frame])[0];
        console.log("Sent message: " + JSON.stringify(sentMessage, null, 4));
        //*/
    }

    close() { // closing socket by sending FIN packet; incoming data will be ignored from that point on
        if (this.state >= ConnectionState.CLOSING) {
            return; // connection is already closing/closed
        }

        this.connected = false;
        this.state = ConnectionState.CLOSING;
        this.socket.end();
    }

    protected onHAPSessionClosed() {
        // If the hap session is closed it is probably also a good idea to close the data stream session
        debug("[%s] HAP session disconnected. Also closing DataStream connection now.", this.remoteAddress);
        this.close();
    }

    protected handleError(error: Error) {
        debug("[%s] Encountered socket error: %s", this.remoteAddress, error.message);
        // handleClose() will be called next
    }

    protected handleClose() {
        this.state = ConnectionState.CLOSED;
        this.connected = false;
        this.emit(DataStreamConnectionEvents.CLOSED);
    }

}
