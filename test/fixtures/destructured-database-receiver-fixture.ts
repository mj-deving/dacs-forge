import type { Database } from "bun:sqlite";

declare const external: (database: Database) => void;
declare const getContainer: () => { readonly db: Database };

const { db } = getContainer();
external(db);
