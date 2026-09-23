declare function recv(type: string, callback: (message: Message) => void): void;
declare function send(message: any, data?: ArrayBuffer | null): void;
declare function ptr(s: string | number): NativePointer;

interface NativePointer {
  readByteArray(length: number): ArrayBuffer;
  writeByteArray(bytes: ArrayBuffer | ArrayLike<number>): void;
}

interface Message {
  payload: any;
  data?: ArrayBuffer | null;
}
