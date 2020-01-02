import createDebug from 'debug';

const debug = createDebug("HTTP:ResponseParser");

export enum ParsingState {
    HEAD,
    HEADERS,
    RESPONSE_BODY,
}

export enum HTTPMethod {
    // noinspection JSUnusedGlobalSymbols
    GET = "GET",
    HEAD = "HEAD",
    POST = "POST",
    PUT = "PUT",
    DELETE = "DELETE",
    CONNECT = "CONNECT",
    OPTIONS = "options",
    TRACE = "TRACE",
}

export enum HTTPHeader {
    // noinspection JSUnusedGlobalSymbols
    CONTENT_TYPE = "Content-Type",
    DATE = "Date",
    CONNECTION = "Connection",
    TRANSFER_ENCODING = "Transfer-Encoding",
    CONTENT_LENGTH = "Content-Length",
}

// 4xx or 5xx response must include an HAP status Code property
export enum HTTPStatus {
    // noinspection JSUnusedGlobalSymbols
    SUCCESS = 200,
    NO_CONTENT = 204,
    MULTI_STATUS = 207,

    BAD_REQUEST = 400, // http client error (e.g. malformed request)
    NOT_FOUND = 404,
    UNPROCESSABLE_ENTITY = 422, // a well-formed request that contains invalid HTTP parameters

    INTERNAL_SERVER_ERROR = 500, // accessory server error (e.g. the operation timed out)
    SERVICE_UNAVAILABLE = 503, // accessory server is too busy to service the request (e.g. reached maximum number of connections)
}

export enum HAPPairingHTTPStatus { // TODO implement status codes
    OK = 200,

    BAD_REQUEST = 400,
    METHOD_NOT_ALLOWED = 405,
    TOO_MANY_REQUEST = 429,
    CONNECTION_AUTHORIZATION_REQUIRED = 470,

    INTERNAL_SERVER_ERROR = 500,
}

export enum HTTPContentType {
    TEXT_HTML = "text/html",
    HAP_JSON = "application/hap+json",
    PAIRING_TLV8 = "application/pairing+tlv8",
}

export enum HTTPRoutes {
    // noinspection JSUnusedGlobalSymbols
    IDENTIFY = '/identify',
    PAIR_SETUP = "/pair-setup",
    PAIR_VERIFY = "/pair-verify",
    PAIRINGS = "/pairings",
    ACCESSORIES = "/accessories",
    CHARACTERISTICS = "/characteristics",
    PREPARE = "/prepare",
    RESOURCE = "/resource",
}

export type HTTPResponse = {
    // header
    messageType: string,
    version: string,
    status: number,
    statusText: string,

    headers: Record<string, string>,

    body: Buffer,
}

export type HTTPRequest = {
    method: HTTPMethod,
    uri: string,
    version: string,

    headers: Record<string, string>,

    body: Buffer,
}

export type HTTPServerResponse = {
    status: HTTPStatus,
    contentType?: HTTPContentType,
    data?: Buffer,
    headers?: Record<string, string>,
}

export abstract class HTTPParser<T> {

    protected state: ParsingState = ParsingState.HEAD;

    protected buffer: Buffer;
    protected readerIndex: number = 0;

    protected constructor() {
        this.buffer = Buffer.alloc(0);
    }

    appendData(buffer: Buffer) {
        this.buffer = Buffer.concat([this.buffer, buffer]);
    }

    abstract parse(): T[];

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
        if (terminatorIndex <= this.buffer.length
            && String.fromCharCode(this.buffer[terminatorIndex]) === '\n') {
            // TODO handle illegal format
            const data = this.buffer.slice(this.readerIndex, minimumRequiredLength);
            this.readerIndex += length + 1;
            return data;
        } else if (terminatorIndex + 1 <= this.buffer.length
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
        const chunk = this.readFixedLengthLine(sizeInt);
        if (chunk === null) { // reset index to the state before we read the size
            this.readerIndex = oldReaderIndex;
        }

        return chunk;
    }

    readFixedLengthBuffer(length: number): Buffer | null {
        if (this.readerIndex + length > this.buffer.length) {
            return null; // not enough data
        }

        const data = this.buffer.slice(this.readerIndex, this.readerIndex + length);
        this.readerIndex += length;
        return data;
    }

}

export class HTTPResponseParser extends HTTPParser<HTTPResponse> {

    private static readonly HTTP_HEADER_PATTERN = /(HTTP|EVENT)\/(\d+\.\d+)\s+(\d{3})\s+(.*?)$/;

    private currentResponse: Partial<HTTPResponse> = {};

    constructor() {
        super();

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

                        this.currentResponse.messageType = messageType;
                        this.currentResponse.version = version;
                        this.currentResponse.status = httpStatus;
                        this.currentResponse.statusText = statusText;

                        this.state = ParsingState.HEADERS;
                        this.currentResponse.headers = {};

                        debug("Successfully parsed HEAD '%s'", head);
                        // fallthrough into next state
                    } else {
                        return finishedResponses; // we couldn't finish parsing
                    }
                case ParsingState.HEADERS:
                    let headerLine;
                    while ((headerLine = this.readStringLine())) {
                        let [name, value] = headerLine.split(/: /, 2);
                        this.currentResponse.headers![name] = value;
                    }

                    if (headerLine === null) {
                        return finishedResponses; // we couldn't finish parsing
                    } else {
                        debug("Successfully parsed headers: %o", this.currentResponse.headers);
                        this.state = ParsingState.RESPONSE_BODY;
                        // fallthrough into next state
                    }
                case ParsingState.RESPONSE_BODY:
                    if (this.currentResponse.status === HTTPStatus.NO_CONTENT) {
                        this.currentResponse.body = Buffer.alloc(0);
                    } else {
                        if (this.currentResponse.headers![HTTPHeader.CONTENT_LENGTH]) { // typically returned by certified accessories
                            const length = parseInt(this.currentResponse.headers![HTTPHeader.CONTENT_LENGTH]);
                            const data = this.readFixedLengthBuffer(length);

                            if (data) {
                                this.currentResponse.body = data;
                            } else { // we could not finish this response, abort
                                return finishedResponses;
                            }
                        } else if (this.currentResponse.headers![HTTPHeader.TRANSFER_ENCODING] === "chunked") { // typically returned by hap-nodejs
                            if (!this.currentResponse.body) {
                                this.currentResponse.body = Buffer.alloc(0);
                            }

                            for(;;) {
                                const chunk = this.readChunk();
                                if (chunk === null) {
                                    return finishedResponses; // we couldn't finish parsing
                                }

                                if (chunk.length === 0) { // we finished parsing
                                    break;
                                }

                                this.currentResponse.body = Buffer.concat([
                                    this.currentResponse.body, chunk
                                ]);
                            }
                        }
                    }

                    finishedResponses.push(this.currentResponse as HTTPResponse);

                    // reset stuff
                    this.currentResponse = {};

                    this.buffer = this.buffer.slice(this.readerIndex, this.buffer.length); // drop read bytes
                    this.readerIndex = 0; // reset reader index
                    this.state = ParsingState.HEAD; // reset state
            }
        }
    }

}

export class HTTPRequestParser extends HTTPParser<HTTPRequest> {

    private static readonly HTTP_HEADER_PATTERN = /(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE)\s+(\/.*?)\s+HTTP\/(\d+\.\d+)$/;

    private currentRequest: Partial<HTTPRequest> = {};

    constructor() {
        super();
    }

    parse(): HTTPRequest[] { // TODO some more abstraction would be great here
        const finishedResponses: HTTPRequest[] = [];

        for(;;) {
            // noinspection FallThroughInSwitchStatementJS
            switch (this.state) {
                case ParsingState.HEAD:
                    const head = this.readStringLine();
                    if (head !== null) {
                        const match = HTTPRequestParser.HTTP_HEADER_PATTERN.exec(head);
                        if (!match) {
                            throw new Error("Unexpected http header format!");
                        }

                        let [, method, uri, version] = match;

                        this.currentRequest.method = method as HTTPMethod;
                        this.currentRequest.uri = uri;
                        this.currentRequest.version = version;

                        this.state = ParsingState.HEADERS;
                        this.currentRequest.headers = {};

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
                        this.currentRequest.headers![name] = value;
                    }

                    if (headerLine === null) {
                        return finishedResponses; // we couldn't finish parsing
                    } else {
                        debug("found headers %o", this.currentRequest.headers);
                        this.state = ParsingState.RESPONSE_BODY;
                        // fallthrough into next state
                    }
                case ParsingState.RESPONSE_BODY:
                    if (this.currentRequest.method === HTTPMethod.POST || this.currentRequest.method === HTTPMethod.PUT) {
                        if (this.currentRequest.headers![HTTPHeader.CONTENT_LENGTH]) { // typically returned by certified accessories
                            const length = parseInt(this.currentRequest.headers![HTTPHeader.CONTENT_LENGTH]);
                            const data = this.readFixedLengthBuffer(length);

                            if (data) {
                                this.currentRequest.body = data;
                            } else { // we could not finish this response, abort
                                return finishedResponses;
                            }
                        } else if (this.currentRequest.headers![HTTPHeader.TRANSFER_ENCODING] === "chunked") { // typically returned by hap-nodejs
                            this.currentRequest.body = Buffer.alloc(0);

                            for(;;) {
                                const chunk = this.readChunk();
                                if (chunk === null) {
                                    return finishedResponses; // we couldn't finish parsing
                                }

                                if (chunk.length === 0) { // we finished parsing
                                    break;
                                }

                                this.currentRequest.body = Buffer.concat([
                                    this.currentRequest.body, chunk
                                ]);
                            }
                        }
                    }

                    finishedResponses.push(this.currentRequest as HTTPRequest);

                    // reset stuff
                    this.currentRequest = {};
                    this.buffer = this.buffer.slice(this.readerIndex, this.buffer.length); // drop read bytes
                    this.readerIndex = 0; // reset reader index
                    this.state = ParsingState.HEAD; // reset state
            }
        }
    }

}
