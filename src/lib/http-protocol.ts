import assert from 'assert';
import {HTTPHeader, HTTPStatus} from "../HAPClient";
import createDebug from 'debug';

const debug = createDebug("HTTP:ResponseParser");

export enum ParsingState {
    HEAD,
    HEADERS,
    RESPONSE_BODY,
}

export type HTTPResponse = {
    // header
    messageType: string;
    version: string;
    status: number;
    statusText: string;

    headers: Record<string, string>;

    body: Buffer;
}

export class HTTPResponseParser {

    private static readonly HTTP_HEADER_PATTERN = /(HTTP|EVENT)\/(\d+\.\d+)\s+(\d{3})\s+(.*?)$/;

    private state: ParsingState = ParsingState.HEAD;

    private buffer: Buffer;
    private readerIndex: number = 0;

    private responseContent: Partial<HTTPResponse> = {};

    constructor() {
        this.buffer = Buffer.alloc(0);
    }

    appendData(buffer: Buffer) {
        this.buffer = Buffer.concat([this.buffer, buffer]);
    }

    parse(): HTTPResponse[] {
        const finishedResponses: HTTPResponse[] = [];

        for(;;) {
            // noinspection FallThroughInSwitchStatementJS
            switch (this.state) {
                case ParsingState.HEAD:
                    const head = this.readStringLine();
                    if (head !== null) {
                        const match = HTTPResponseParser.HTTP_HEADER_PATTERN.exec(head);
                        if (!match) {
                            throw new Error("Unexpected http header format!");
                        }

                        let [, messageType, version, status, statusText] = match;
                        const httpStatus = parseInt(status);

                        this.responseContent.messageType = messageType;
                        this.responseContent.version = version;
                        this.responseContent.status = httpStatus;
                        this.responseContent.statusText = statusText;

                        this.state = ParsingState.HEADERS;
                        this.responseContent.headers = {};

                        debug("Successfully parsed HEAD '%s'", head);
                        // fallthrough into next state
                    } else {
                        return finishedResponses; // we couldn't finish parsing
                    }
                case ParsingState.HEADERS:
                    let headerLine;
                    while ((headerLine = this.readStringLine())) {
                        let [name, value] = headerLine.split(/: /, 2);
                        debug("Successfully parse header '%s'='%s'", name, value);
                        this.responseContent.headers![name] = value;
                    }

                    if (headerLine === null) {
                        return finishedResponses; // we couldn't finish parsing
                    } else {
                        debug("found headers %o", this.responseContent.headers);
                        this.state = ParsingState.RESPONSE_BODY;
                        // fallthrough into next state
                    }
                case ParsingState.RESPONSE_BODY:
                    if (this.responseContent.status === HTTPStatus.NO_CONTENT) {
                        this.responseContent.body = Buffer.alloc(0);
                    } else {
                        if (this.responseContent.headers![HTTPHeader.CONTENT_LENGTH]) {
                            /*
                        let len = parseInt(headers['content-length']);
                    debug(`Reading ${len} bytes for body...`);
                    debug(`There are ${buffer::remaining()} bytes left in the buffer`);
                    if (buffer::remaining() >= len) {
                        body.append(buffer.nextBuffer(len));
                    } else {
                        // the whole message is not in the buffer
                        // wait till next time
                        debug('partial message; returning');
                        return [ [], buffer.buf ];
                    }
                         */
                        } else if (this.responseContent.headers![HTTPHeader.TRANSFER_ENCODING] === "chunked") { // TODO enum
                            this.responseContent.body = Buffer.alloc(0);

                            for(;;) {
                                const chunk = this.readChunk();
                                if (chunk === null) {
                                    return finishedResponses; // we couldn't finish parsing
                                }

                                if (chunk.length === 0) { // we finished parsing
                                    break;
                                }

                                this.responseContent.body = Buffer.concat([
                                    this.responseContent.body, chunk
                                ]);
                            }
                        }
                    }

                    finishedResponses.push(this.responseContent as HTTPResponse);

                    // reset stuff
                    this.responseContent = {};
                    this.buffer = this.buffer.slice(this.readerIndex, this.buffer.length); // drop read bytes
                    this.readerIndex = 0; // reset reader index
                    this.state = ParsingState.HEAD; // reset state
            }
        }
    }

    readLine(): Buffer | null {
        let previousWasR = false; // previous character was '\r'

        for (let i = this.readerIndex; i < this.buffer.length; i++) {
            const character = String.fromCharCode(this.buffer[i]);

            if (character === '\r') {
                previousWasR = true;
                continue
            } else if (character === '\n') {
                const endIndex = previousWasR? i-1: i;
                const line = this.buffer.slice(this.readerIndex, endIndex);
                this.readerIndex = i + 1;
                return line;
            }

            if (previousWasR) {
                previousWasR = false;
            }
        }

        return null;
    }

    readFixedLengthLine(length: number): Buffer | null {
        const minimumRequiredLength = this.readerIndex + length;
        if (minimumRequiredLength > this.buffer.length) {
            return null; // there is not even enough data to fit the chunk
        }

        const terminatorIndex = minimumRequiredLength;
        if (terminatorIndex < this.buffer.length
            && String.fromCharCode(this.buffer[terminatorIndex]) === '\n') {
            // TODO handle illegal format
            const data = this.buffer.slice(this.readerIndex, minimumRequiredLength);
            this.readerIndex += length + 1;
            return data;
        } else if (terminatorIndex + 1 < this.buffer.length
            && String.fromCharCode(this.buffer[terminatorIndex]) === "\r" && String.fromCharCode(this.buffer[terminatorIndex+ 1]) === "\n") {
            // TODO handle illegal format
            const data = this.buffer.slice(this.readerIndex, minimumRequiredLength);
            this.readerIndex += length + 2;
            return data;
        }

        return null; // not enough data
    }

    readStringLine(): string | null {
        const line = this.readLine();
        return line !== null? line.toString(): null;
    }

    readChunk(): Buffer | null {
        const oldReaderIndex = this.readerIndex;

        const size = this.readStringLine();
        if (size === null) {
            this.readerIndex = oldReaderIndex; // reset index to the state before we read the size
            return null; // indicates not enough data
        }

        const sizeInt = parseInt(size, 16); // lol
        // sizeInt == 0 indicates end of chunked data
        return this.readFixedLengthLine(sizeInt);
    }

}
