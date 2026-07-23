declare const metadata: { run: unknown };
declare function externalSink(value: unknown): void;

externalSink(metadata.run);
