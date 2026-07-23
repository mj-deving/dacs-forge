export interface SqliteMutation {
  readonly keyword: string;
  readonly operation: "delete" | "insert" | "schema" | "update";
  readonly table?: string;
}

const SCHEMA_MUTATIONS = new Set([
  "ALTER", "ANALYZE", "ATTACH", "CREATE", "DETACH", "DROP", "PRAGMA", "REINDEX", "VACUUM",
]);
const COMMAND_PRAGMAS = new Set([
  "incremental_vacuum", "optimize", "shrink_memory", "wal_checkpoint",
]);
const READ_ONLY_ARGUMENT_PRAGMAS = new Set([
  "foreign_key_check", "foreign_key_list", "index_info", "index_list", "index_xinfo",
  "integrity_check", "quick_check", "table_info", "table_list", "table_xinfo",
]);
const ATOMIC_WRITE_MARKER = /\/\*\s*atomic-write:\s*([a-z0-9.-]+)\s*\*\//gim;

export function classifySqliteMutations(sql: string): readonly SqliteMutation[] {
  const mutations: SqliteMutation[] = [];
  for (const statement of splitSqlStatements(tokenizeSql(sql))) {
    const mutation = classifyStatement(statement);
    if (mutation !== null) mutations.push(mutation);
  }
  return mutations;
}

export function containsSqliteTransactionControl(sql: string): boolean {
  return splitSqlStatements(tokenizeSql(sql)).some((statement) => {
    const first = statement[0];
    return first?.kind === "word" && [
      "BEGIN", "COMMIT", "END", "RELEASE", "ROLLBACK", "SAVEPOINT",
    ].includes(first.text.toUpperCase());
  });
}

export function sqliteBlockComments(sql: string): readonly string[] {
  const comments: string[] = [];
  tokenizeSql(sql, (comment) => comments.push(comment));
  return comments;
}

export function sqliteAtomicWriteMarkerIds(sql: string): readonly string[] {
  return sqliteBlockComments(sql)
    .flatMap((comment) => [...comment.matchAll(ATOMIC_WRITE_MARKER)].map((match) => match[1]!));
}

interface SqlToken {
  readonly kind: "identifier" | "punctuation" | "string" | "word";
  readonly text: string;
}

function splitSqlStatements(tokens: readonly SqlToken[]): SqlToken[][] {
  const statements: SqlToken[][] = [];
  let statementStart = 0;
  let depth = 0;
  let triggerBody = false;
  let triggerCaseDepth = 0;
  let triggerEnd = false;
  for (let index = 0; index <= tokens.length; index += 1) {
    const token = tokens[index];
    const inTrigger = isCreateTrigger(tokens, statementStart);
    const keyword = token?.kind === "word" ? token.text.toUpperCase() : undefined;
    if (inTrigger && keyword === "BEGIN" && !triggerBody) triggerBody = true;
    else if (inTrigger && triggerBody && keyword === "CASE") triggerCaseDepth += 1;
    else if (inTrigger && triggerBody && keyword === "END") {
      if (triggerCaseDepth > 0) triggerCaseDepth -= 1;
      else triggerEnd = true;
    }
    if (token?.kind === "punctuation" && token.text === "(") depth += 1;
    else if (token?.kind === "punctuation" && token.text === ")") depth = Math.max(0, depth - 1);
    const statementEnd = index === tokens.length
      || (token?.kind === "punctuation" && token.text === ";"
        && depth === 0 && (!inTrigger || triggerEnd));
    if (statementEnd) {
      const statement = tokens.slice(statementStart, index);
      if (statement.length > 0) statements.push(statement);
      statementStart = index + 1;
      triggerBody = false;
      triggerCaseDepth = 0;
      triggerEnd = false;
    }
  }
  return statements;
}

function isCreateTrigger(tokens: readonly SqlToken[], start: number): boolean {
  if (tokens[start]?.kind !== "word" || tokens[start]?.text.toUpperCase() !== "CREATE") return false;
  const next = tokens[start + 1]?.kind === "word" ? tokens[start + 1]!.text.toUpperCase() : undefined;
  return next === "TRIGGER"
    || ((next === "TEMP" || next === "TEMPORARY")
      && tokens[start + 2]?.kind === "word" && tokens[start + 2]!.text.toUpperCase() === "TRIGGER");
}

function classifyStatement(tokens: readonly SqlToken[]): SqliteMutation | null {
  let index = 0;
  if (keyword(tokens[index]) === "EXPLAIN") return null;
  let depth = 0;
  for (; index < tokens.length; index += 1) {
    const current = tokens[index]!;
    if (current.kind === "punctuation" && current.text === "(") {
      depth += 1;
      continue;
    }
    if (current.kind === "punctuation" && current.text === ")") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth !== 0) continue;
    const command = keyword(current);
    if (command === undefined) continue;
    if (command === "INSERT" || command === "REPLACE") {
      const into = tokens.slice(index + 1).findIndex((candidate) => keyword(candidate) === "INTO");
      const table = into === -1 ? undefined : qualifiedIdentifier(tokens, index + 1 + into + 1);
      return { keyword: command, operation: "insert", ...(table === undefined ? {} : { table }) };
    }
    if (command === "UPDATE") {
      let tableIndex = index + 1;
      if (keyword(tokens[tableIndex]) === "OR") tableIndex += 2;
      const table = qualifiedIdentifier(tokens, tableIndex);
      return { keyword: command, operation: "update", ...(table === undefined ? {} : { table }) };
    }
    if (command === "DELETE") {
      const from = tokens.slice(index + 1).findIndex((candidate) => keyword(candidate) === "FROM");
      const table = from === -1 ? undefined : qualifiedIdentifier(tokens, index + 1 + from + 1);
      return { keyword: command, operation: "delete", ...(table === undefined ? {} : { table }) };
    }
    if (command === "PRAGMA") {
      let nameIndex = index + 1;
      if (identifier(tokens[nameIndex]) !== undefined
        && tokens[nameIndex + 1]?.kind === "punctuation" && tokens[nameIndex + 1]?.text === "."
        && identifier(tokens[nameIndex + 2]) !== undefined) nameIndex += 2;
      const name = identifier(tokens[nameIndex])?.toLowerCase();
      const tail = tokens.slice(nameIndex + 1);
      const writable = tail.some((candidate) => candidate.kind === "punctuation" && candidate.text === "=")
        || (name !== undefined && COMMAND_PRAGMAS.has(name))
        || (tail[0]?.kind === "punctuation" && tail[0].text === "("
          && (name === undefined || !READ_ONLY_ARGUMENT_PRAGMAS.has(name)));
      return writable ? { keyword: command, operation: "schema" } : null;
    }
    if (SCHEMA_MUTATIONS.has(command)) return { keyword: command, operation: "schema" };
  }
  return null;
}

function keyword(token: SqlToken | undefined): string | undefined {
  return token?.kind === "word" ? token.text.toUpperCase() : undefined;
}

function identifier(token: SqlToken | undefined): string | undefined {
  if (token?.kind === "identifier") return token.text;
  return token?.kind === "word" && /^[A-Za-z_][A-Za-z0-9_$]*$/.test(token.text)
    ? token.text : undefined;
}

function qualifiedIdentifier(tokens: readonly SqlToken[], index: number): string | undefined {
  const first = identifier(tokens[index]);
  if (first === undefined) return undefined;
  return tokens[index + 1]?.kind === "punctuation" && tokens[index + 1]?.text === "."
    ? identifier(tokens[index + 2])
    : first;
}

function tokenizeSql(sql: string, onBlockComment?: (comment: string) => void): SqlToken[] {
  const tokens: SqlToken[] = [];
  for (let index = 0; index < sql.length;) {
    const char = sql[index]!;
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "-" && sql[index + 1] === "-") {
      const end = sql.indexOf("\n", index + 2);
      index = end === -1 ? sql.length : end + 1;
      continue;
    }
    if (char === "/" && sql[index + 1] === "*") {
      const end = sql.indexOf("*/", index + 2);
      if (end === -1) throw new Error("Unterminated SQLite block comment");
      onBlockComment?.(sql.slice(index, end + 2));
      index = end + 2;
      continue;
    }
    if (char === "'" || char === '"' || char === "`" || char === "[") {
      const close = char === "[" ? "]" : char;
      let value = "";
      let closed = false;
      index += 1;
      while (index < sql.length) {
        if (sql[index] === close) {
          if (sql[index + 1] === close && close !== "]") {
            value += close;
            index += 2;
            continue;
          }
          index += 1;
          closed = true;
          break;
        }
        value += sql[index]!;
        index += 1;
      }
      if (!closed) throw new Error(`Unterminated SQLite quoted region starting with ${char}`);
      tokens.push({ kind: char === "'" ? "string" : "identifier", text: value });
      continue;
    }
    if (/[A-Za-z_]/.test(char)) {
      const match = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(sql.slice(index))!;
      tokens.push({ kind: "word", text: match[0] });
      index += match[0].length;
      continue;
    }
    if ("();=,.".includes(char)) tokens.push({ kind: "punctuation", text: char });
    index += 1;
  }
  return tokens;
}
