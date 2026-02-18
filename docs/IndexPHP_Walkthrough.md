# TransactiWar — `index.php` Walkthrough

This file is a **diagnostic health-check endpoint**, not the application's main entry point.
Its job is to verify that PHP is running, environment variables are configured, and the
database is reachable — and to do all of that without leaking internal details to anyone who
shouldn't see them.

---

## Step 1: Strict Types

```php
declare(strict_types=1);
```

This is the first line of the file, before anything else. It tells PHP to enforce strict type
checking for all function calls in this file. Without it, PHP silently coerces types — for
example, passing the integer `1` where a `string` is expected would succeed. With strict
types, that would throw a `TypeError`.

For a security-sensitive application, implicit coercion is a source of subtle bugs. Declaring
strict types forces you to be explicit and catches type mismatches at runtime rather than
letting them silently produce wrong values.

---

## Step 2: Security Headers

```php
header('Content-Type: text/plain; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
```

Three HTTP response headers are set before any output.

**`Content-Type: text/plain; charset=UTF-8`** — tells the browser this response is plain
text, not HTML. Without this, a browser might try to render any HTML-like content in the
response, opening the door to reflected XSS if user-controlled data ever appeared in the
output. Plain text is safe — browsers display it literally.

**`X-Content-Type-Options: nosniff`** — instructs the browser not to "sniff" the content
type and override what the server declared. Some browsers would look at the response body and
decide it looks like HTML or JavaScript, ignoring the `Content-Type` header. `nosniff`
prevents this — the browser must trust the declared type.

**`Cache-Control: no-store`** — prevents the response from being cached anywhere: browser
cache, CDN, or intermediate proxy. Diagnostic output (table names, connection status) is
internal information that should never be stored in a cache that another user or request
could read.

---

## Step 3: Liveness Probe

```php
echo "PHP running\n";
```

This line runs unconditionally — before the diagnostic gate, before any environment variable
check, before any database connection. It is a minimal liveness signal: if a request reaches
this file and this line executes, PHP is alive and serving requests. This is useful for
infrastructure monitoring and is safe to expose publicly because it reveals nothing sensitive.

---

## Step 4: `requireEnv()` — Fail-Safe Configuration Loading

```php
function requireEnv(string $key): string
{
    $value = getenv($key);
    if ($value === false || $value === '') {
        http_response_code(500);
        echo "Missing required server configuration.\n";
        exit(1);
    }
    return $value;
}
```

This helper function retrieves an environment variable and fails loudly if it is missing or
empty. Several decisions here are deliberate:

**`=== false || === ''`** — `getenv()` returns `false` if the variable doesn't exist, and
an empty string `''` if it exists but was set to nothing. Both cases are treated as missing.
A blank database password, for example, would be just as broken as a missing one.

**The error message is generic.** It says "Missing required server configuration" — not
"Missing MYSQL_PASSWORD" or "MYSQL_HOST not set." Revealing which specific variable is
missing would help an attacker understand the application's configuration structure. The
actual variable name is logged nowhere in the response.

**`http_response_code(500)`** — a configuration error is the server's problem, not the
client's. `500 Internal Server Error` is the correct status code.

**`exit(1)`** — execution stops immediately. There is no code path that continues with a
broken configuration.

---

## Step 5: Strict MySQLi Error Reporting

```php
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
```

By default, MySQLi silently returns `false` on failure and sets an error code you have to
check manually. This is easy to forget, and unchecked failures can cause logic errors that
are security-relevant (e.g., assuming a query succeeded when it didn't).

`MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT` changes this: any MySQLi error now throws a
`mysqli_sql_exception`. This means failures are impossible to accidentally ignore — they
always surface as exceptions that must be caught. The `try/catch` block later in the file
handles them.

This line is placed before the diagnostic gate so that it applies to the entire execution
context, including any MySQLi calls that might be added later.

---

## Step 6: Diagnostic Gate

```php
if (getenv('APP_DIAGNOSTIC_MODE') !== '1') {
    echo "Diagnostic mode disabled.\n";
    exit(0);
}
```

Everything from here on reveals internal information: table names, database connectivity,
environment variable values. This gate ensures none of that is shown unless the server is
explicitly configured with `APP_DIAGNOSTIC_MODE=1`.

The comparison is `!== '1'` (strict string equality) rather than a loose check like `!= 1`
or a truthy check. This means only the exact string `'1'` enables diagnostic mode — not `'true'`,
not `'yes'`, not `'on'`. Accidental or unexpected values are treated as disabled.

In the Docker Compose file, `APP_DIAGNOSTIC_MODE` defaults to `0`, meaning diagnostic mode
is off unless you explicitly set it. A production deployment that forgets to set it stays
safe by default.

---

## Step 7: Environment Variables for Database

```php
$host   = requireEnv('MYSQL_HOST');
$user   = requireEnv('MYSQL_USER');
$pass   = requireEnv('MYSQL_PASSWORD');
$dbName = requireEnv('MYSQL_DATABASE');
```

Each variable is loaded through `requireEnv()`, which aborts with a generic error if any is
missing. Note that these four calls only execute when diagnostic mode is on — credentials are
only fetched when the code actually needs them.

---

## Step 8: Database Connection and Table Listing

```php
try {
    $mysqli = new mysqli($host, $user, $pass, $dbName);
    $mysqli->set_charset('utf8mb4');
    $result = $mysqli->query('SHOW TABLES');
    echo "Tables:\n";
    while ($row = $result->fetch_array(MYSQLI_NUM)) {
        $tableName = preg_replace('/[^A-Za-z0-9_]/', '?', (string) $row[0]);
        echo "- {$tableName}\n";
    }
    $result->free();
    $mysqli->close();
} catch (mysqli_sql_exception $exception) {
    error_log('Database operation failed: ' . $exception->getMessage());
    http_response_code(500);
    echo "Database operation failed.\n";
    exit(1);
}
```

### Connection

```php
$mysqli = new mysqli($host, $user, $pass, $dbName);
$mysqli->set_charset('utf8mb4');
```

`set_charset('utf8mb4')` sets the connection's character set explicitly after connecting.
This is important — if the connection character set doesn't match the database, string
comparisons and data round-trips can produce incorrect results or encoding errors.

### Output Sanitisation

```php
$tableName = preg_replace('/[^A-Za-z0-9_]/', '?', (string) $row[0]);
```

Even though table names come from `SHOW TABLES` (not user input), they are sanitised before
being written to the response. The regex strips anything that isn't an alphanumeric character
or underscore, replacing it with `?`. A table name that somehow contained characters
meaningful in HTML or a terminal (`<`, `>`, escape sequences) cannot do anything harmful in
the output. This is a good habit — sanitise output regardless of where it came from.

### Resource Cleanup

```php
$result->free();
$mysqli->close();
```

The result set and connection are explicitly freed and closed. PHP cleans these up at script
end anyway, but explicit cleanup is clearer about intent and better practice in files that
might eventually do more work before exiting.

### Error Handling

```php
} catch (mysqli_sql_exception $exception) {
    error_log('Database operation failed: ' . $exception->getMessage());
    http_response_code(500);
    echo "Database operation failed.\n";
    exit(1);
}
```

The exception message — which contains the actual SQL error, table names, or other internal
details — goes to `error_log()`, which writes to the server's error log (visible to the
operator, not to the client). The response body gets only the generic string "Database
operation failed." The client learns that something went wrong, but not what or why.

---

## Summary

| Concern | How It Is Handled |
|---|---|
| PHP liveness | Unconditional `echo "PHP running"` before any gate |
| Diagnostic info gated | `APP_DIAGNOSTIC_MODE !== '1'` required to proceed |
| Missing config fails safely | `requireEnv()` aborts with generic message, no var names leaked |
| DB errors don't leak details | Exception message goes to `error_log`, not the response |
| Output cannot contain injected content | Table names sanitised with `preg_replace` |
| DB failures cannot be silently ignored | `mysqli_report(MYSQLI_REPORT_ERROR \| MYSQLI_REPORT_STRICT)` |
| Response not cached | `Cache-Control: no-store` |
| Browser cannot misinterpret output | `Content-Type: text/plain` + `X-Content-Type-Options: nosniff` |
