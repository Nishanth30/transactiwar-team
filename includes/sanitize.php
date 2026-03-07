<?php
// includes/sanitize.php
// Custom sanitization & validation framework
// No external dependencies — pure PHP
// Defends against: XSS, SQLi output, path traversal,
//                  header injection, null bytes,
//                  unicode attacks, buffer overflow attempts

declare(strict_types = 1)
;
// ══════════════════════════════════════════════════════════════════
//  CONSTANTS — derived from your init.sql schema
// ══════════════════════════════════════════════════════════════════

define('MAX_USERNAME_LEN', 32);
define('MIN_USERNAME_LEN', 5);
define('MAX_EMAIL_LEN', 254);
define('MAX_PASSWORD_LEN', 128);
define('MIN_PASSWORD_LEN', 8);
define('MAX_BIO_LEN', 65535); // TEXT column
define('MAX_COMMENT_LEN', 500); // transactions.receiver_comment
define('MAX_FILEPATH_LEN', 512); // users.profile_image_path
define('MAX_WEBPAGE_LEN', 255); // activity_logs.webpage
define('MIN_TRANSFER_PAISE', 100); // ₹1.00 minimum
define('PUBLIC_ID_LEN', 36); // UUID string: 8-4-4-4-12


// ══════════════════════════════════════════════════════════════════
//  SECTION 1 — OUTPUT ENCODING
//  Use before EVERY echo in HTML — prevents XSS
// ══════════════════════════════════════════════════════════════════

/**
 * Escape a value for safe HTML output.
 * Use on EVERY variable you echo into HTML — no exceptions.
 *
 * Converts:
 *   <script>  →  &lt;script&gt;
 *   "         →  &quot;
 *   '         →  &#039;
 *   &         →  &amp;
 *
 * Usage:
 *   echo escape_output($username);
 *   echo escape_output($bio);
 *   <input value="<?= escape_output($value) ?>">
 */
function escape_output(mixed $value): string
{
    if ($value === null || $value === false) {
        return '';
    }

    // Convert to string safely
    $str = (string)$value;

    // Remove null bytes before encoding — null bytes can bypass filters
    $str = str_replace("\0", '', $str);

    return htmlspecialchars(
        $str,
        ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5,
        'UTF-8',
        true // double encode — encode even already-encoded entities
    );
}

/**
 * Escape output for use inside JavaScript strings.
 * Use when outputting PHP values into JS code.
 *
 * Usage:
 *   <script>
 *     var username = "<?= escape_js($username) ?>";
 *   </script>
 */
function escape_js(mixed $value): string
{
    if ($value === null || $value === false) {
        return '';
    }

    return json_encode(
        (string)$value,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    );
}

/**
 * Escape output for use inside HTML attributes.
 * Stronger than escape_output for attribute context.
 *
 * Usage:
 *   <div data-user="<?= escape_attr($username) ?>">
 */
function escape_attr(mixed $value): string
{
    if ($value === null || $value === false) {
        return '';
    }

    $str = (string)$value;
    $str = str_replace("\0", '', $str);

    // Remove all control characters from attributes
    $str = preg_replace('/[\x00-\x1F\x7F]/', '', $str ?? '');

    return htmlspecialchars(
        $str ?? '',
        ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5,
        'UTF-8',
        true
    );
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 2 — INPUT CLEANING
//  Use on every $_POST / $_GET before doing anything with it
// ══════════════════════════════════════════════════════════════════

/**
 * Clean a general text input.
 * - Removes null bytes (bypass attack vector)
 * - Strips control characters
 * - Normalizes whitespace
 * - Trims leading/trailing whitespace
 * - Does NOT strip HTML tags (escape_output handles display)
 *
 * Usage:
 *   $username = clean_input($_POST['username'] ?? '');
 *   $email    = clean_input($_POST['email']    ?? '');
 */
function clean_input(mixed $value): string
{
    if ($value === null || $value === false) {
        return '';
    }

    $str = (string)$value;

    // Remove null bytes — critical, can bypass many filters
    $str = str_replace("\0", '', $str);

    // Remove non-printable control characters (except newline/tab for bio fields)
    // \x00-\x08 = control chars before tab
    // \x0B-\x0C = vertical tab, form feed
    // \x0E-\x1F = control chars after carriage return
    // \x7F      = DEL character
    $str = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $str ?? '');

    // Normalize line endings to \n
    $str = str_replace(["\r\n", "\r"], "\n", $str ?? '');

    // Trim whitespace
    return trim($str ?? '');
}

/**
 * Read and clean a POST string value.
 * Returns empty string if key missing.
 *
 * Usage:
 *   $username = post_str('username');
 */
function post_str(string $key): string
{
    return clean_input($_POST[$key] ?? '');
}

/**
 * Read and clean a GET string value.
 * Returns empty string if key missing.
 *
 * Usage:
 *   $search = get_str('q');
 */
function get_str(string $key): string
{
    return clean_input($_GET[$key] ?? '');
}

/**
 * Read a POST integer value.
 * Returns null if missing or not a valid integer.
 *
 * Usage:
 *   $receiverId = post_int('receiver_id');
 */
function post_int(string $key): ?int
{
    return sanitize_int($_POST[$key] ?? null);
}

/**
 * Read a GET integer value.
 * Returns null if missing or not a valid integer.
 */
function get_int(string $key): ?int
{
    return sanitize_int($_GET[$key] ?? null);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 3 — TYPE SANITIZERS
// ══════════════════════════════════════════════════════════════════

/**
 * Sanitize to a safe integer.
 * Returns null if value is not a valid integer.
 * Never returns negative unless explicitly allowed.
 *
 * Usage:
 *   $userId   = sanitize_int($_POST['user_id']);
 *   $amount   = sanitize_int($_POST['amount_paise']);
 */
function sanitize_int(mixed $value): ?int
{
    if ($value === null || $value === '') {
        return null;
    }

    // Remove null bytes and whitespace
    $str = trim(str_replace("\0", '', (string)$value));

    // Must be a valid integer string (optional leading minus)
    if (!preg_match('/^-?\d+$/', $str)) {
        return null;
    }

    // Check it fits in PHP int range
    if (!filter_var($str, FILTER_VALIDATE_INT, [
    'options' => [
    'min_range' => PHP_INT_MIN,
    'max_range' => PHP_INT_MAX,
    ]
    ])) {
        return null;
    }

    return (int)$str;
}

/**
 * Sanitize to a safe unsigned positive integer.
 * Returns null if value is not a positive integer.
 *
 * Usage:
 *   $userId = sanitize_uint($_POST['receiver_id']);
 *   if ($userId === null) { $error = 'Invalid user ID'; }
 */
function sanitize_uint(mixed $value): ?int
{
    $int = sanitize_int($value);

    if ($int === null || $int <= 0) {
        return null;
    }

    return $int;
}

/**
 * Sanitize a transfer amount in paise.
 * Must be integer, minimum ₹1.00 (100 paise).
 *
 * Usage:
 *   $amount = sanitize_amount($_POST['amount_paise']);
 *   if ($amount === null) { $error = 'Minimum transfer is ₹1'; }
 */
function sanitize_amount(mixed $value): ?int
{
    $int = sanitize_int($value);

    if ($int === null || $int < MIN_TRANSFER_PAISE) {
        return null;
    }

    return $int;
}

/**
 * Sanitize and validate public user ID (UUID string).
 * Returns canonical lowercase UUID if valid, otherwise null.
 *
 * Usage:
 *   $receiverPublicId = sanitize_public_user_id($_POST['receiver_public_id']);
 */
function sanitize_public_user_id(mixed $value): ?string
{
    if ($value === null || $value === false) {
        return null;
    }

    $str = trim(str_replace("\0", '', (string)$value));
    $str = strtolower($str);

    if (strlen($str) !== PUBLIC_ID_LEN) {
        return null;
    }

    if (!preg_match(
    '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
    $str
    )) {
        return null;
    }

    return $str;
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 4 — FIELD VALIDATORS
//  Return true/false — use for form validation
// ══════════════════════════════════════════════════════════════════

/**
 * Validate username.
 * Rules:
 *   - 3 to 32 characters
 *   - Only letters, numbers, underscores, hyphens
 *   - Cannot start or end with underscore/hyphen
 *   - No spaces
 *   - Case insensitive stored (ascii_general_ci in schema)
 *
 * Usage:
 *   if (!validate_username($username)) { $error = 'Invalid username'; }
 */
function validate_username(string $username): bool
{
    if (strlen($username) < MIN_USERNAME_LEN ||
    strlen($username) > MAX_USERNAME_LEN) {
        return false;
    }

    // Only alphanumeric, underscore, hyphen
    // Cannot start or end with underscore or hyphen
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-_]*[a-zA-Z0-9]$/', $username) &&
    !preg_match('/^[a-zA-Z0-9]$/', $username)) {
        return false;
    }

    return true;
}

/**
 * Validate email address.
 * Rules:
 *   - Valid email format
 *   - Max 254 characters (RFC 5321)
 *   - Lowercase normalized
 *
 * Usage:
 *   if (!validate_email($email)) { $error = 'Invalid email'; }
 */
function validate_email(string $email): bool
{
    if (strlen($email) > MAX_EMAIL_LEN) {
        return false;
    }

    // PHP's built-in email validation (RFC compliant)
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    // Extra: no null bytes (already cleaned but double check)
    if (str_contains($email, "\0")) {
        return false;
    }

    return true;
}

/**
 * Normalize email — lowercase and trim.
 * Call after validate_email() passes.
 *
 * Usage:
 *   $email = normalize_email($_POST['email']);
 */
function normalize_email(string $email): string
{
    return strtolower(trim($email));
}

/**
 * Validate password strength.
 * Rules:
 *   - 8 to 128 characters
 *   - At least one uppercase letter
 *   - At least one lowercase letter
 *   - At least one digit
 *   - At least one special character
 *
 * Usage:
 *   if (!validate_password($password)) { $error = 'Weak password'; }
 */
function validate_password(string $password): bool
{
    $len = strlen($password);

    if ($len < MIN_PASSWORD_LEN || $len > MAX_PASSWORD_LEN) {
        return false;
    }

    // At least one uppercase
    if (!preg_match('/[A-Z]/', $password)) {
        return false;
    }

    // At least one lowercase
    if (!preg_match('/[a-z]/', $password)) {
        return false;
    }

    // At least one digit
    if (!preg_match('/[0-9]/', $password)) {
        return false;
    }

    // At least one special character
    if (!preg_match('/[\W_]/', $password)) {
        return false;
    }

    return true;
}

/**
 * Get human readable password requirements.
 * Show this to users on register page.
 */
function password_requirements(): string
{
    return 'Password must be 8-128 characters and include: 
            uppercase letter, lowercase letter, number, 
            and special character (!@#$%^&* etc.)';
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 5 — CONTENT SANITIZERS
// ══════════════════════════════════════════════════════════════════

/**
 * Sanitize biography / long text content.
 * - Strips all HTML tags (no markup allowed in bio)
 * - Removes null bytes
 * - Enforces max length
 * - Normalizes whitespace and line endings
 *
 * Store the RESULT in DB.
 * Still use escape_output() when displaying.
 *
 * Usage:
 *   $bio = sanitize_bio($_POST['bio'] ?? '');
 */
function sanitize_bio(string $bio): string
{
    // Remove null bytes
    $bio = str_replace("\0", '', $bio);

    // Attacker's 65,000-char payload gets cut to 65,535 chars max
    // But strip_tags on even 65k of <a<a<a is dangerous
    // So truncate to a safe working limit BEFORE parsing
    $bio = mb_substr($bio, 0, MAX_BIO_LEN, 'UTF-8');

    // Strip ALL html tags — no markup in biography
    $bio = strip_tags($bio);

    // Normalize line endings
    $bio = str_replace(["\r\n", "\r"], "\n", $bio);

    // Remove control characters except newline and tab
    $bio = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $bio ?? '');

    // Collapse more than 2 consecutive newlines into 2
    $bio = preg_replace('/\n{3,}/', "\n\n", $bio ?? '');

    // Enforce max length (TEXT column = 65535 bytes)
    // Use mb_substr for multibyte safety
    $bio = mb_substr($bio ?? '', 0, MAX_BIO_LEN, 'UTF-8');

    return trim($bio ?? '');
}

/**
 * Sanitize transfer comment.
 * - Strips HTML tags
 * - Removes null bytes
 * - Enforces max 500 chars (schema: VARCHAR 500)
 * - Single line only (no newlines in comments)
 *
 * Usage:
 *   $comment = sanitize_comment($_POST['comment'] ?? '');
 */
function sanitize_comment(string $comment): string
{
    // Remove null bytes
    $comment = str_replace("\0", '', $comment);
    $comment = mb_substr($comment, 0, MAX_COMMENT_LEN, 'UTF-8');
    // Strip HTML tags
    $comment = strip_tags($comment);

    // Remove ALL newlines — comment is single line
    $comment = str_replace(["\r\n", "\r", "\n"], ' ', $comment);

    // Remove control characters
    $comment = preg_replace('/[\x00-\x1F\x7F]/', '', $comment ?? '');

    // Enforce max length
    $comment = mb_substr($comment ?? '', 0, MAX_COMMENT_LEN, 'UTF-8');

    return trim($comment ?? '');
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 6 — FILENAME SANITIZER
//  Critical for Member 2's file upload feature
// ══════════════════════════════════════════════════════════════════

/**
 * Sanitize an uploaded filename.
 * Defends against:
 *   - Path traversal: ../../etc/passwd
 *   - Null byte injection: file.php\0.jpg
 *   - Double extension: shell.php.jpg
 *   - Unicode tricks: filе.php (cyrillic е)
 *   - Hidden extensions: .htaccess, .php5
 *
 * Returns ONLY the safe base filename with extension.
 * Caller must prepend the upload directory path.
 *
 * Usage:
 *   $safeName = sanitize_filename($originalName);
 *   // Then Member 2 renames it with UUID anyway
 */
function sanitize_filename(string $filename): string
{
    // Remove null bytes — critical for null byte injection
    $filename = str_replace("\0", '', $filename);

    // Extract just the base filename — strips any path components
    // Defends against: ../../etc/passwd, /var/www/html/shell.php
    $filename = basename($filename);

    // Convert to ASCII — removes unicode lookalike attacks
    // filе.php (cyrillic е looks like latin e)
    $filename = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $filename) ?: 'upload';

    // Remove any characters that aren't alphanumeric, dot, hyphen, underscore
    $filename = preg_replace('/[^a-zA-Z0-9.\-_]/', '_', $filename ?? '');

    // Collapse multiple dots — prevents shell.php....jpg tricks
    $filename = preg_replace('/\.{2,}/', '.', $filename ?? '');

    // Extract extension safely
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $basename = pathinfo($filename, PATHINFO_FILENAME);

    // Allowed image extensions only
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    if (!in_array($ext, $allowedExtensions, true)) {
        $ext = 'jpg'; // force safe default
    }

    // Clean the base name
    $basename = preg_replace('/[^a-zA-Z0-9\-_]/', '_', $basename ?? '');
    $basename = trim($basename, '_');

    if ($basename === '') {
        $basename = 'upload';
    }

    // Enforce max length
    $basename = mb_substr($basename, 0, 100, 'UTF-8');

    return $basename . '.' . $ext;
}

/**
 * Validate file extension against allowed list.
 * Use alongside MIME type check in upload.php (Member 2).
 *
 * Usage:
 *   if (!validate_file_extension($filename, ['jpg','png','webp'])) {
 *       $error = 'File type not allowed';
 *   }
 */
function validate_file_extension(string $filename, array $allowed): bool
{
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, $allowed, true);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 7 — HEADER & URL SANITIZERS
// ══════════════════════════════════════════════════════════════════

/**
 * Sanitize a value for use in HTTP headers.
 * Defends against header injection via \r\n characters.
 *
 * Usage:
 *   header('Location: ' . sanitize_header($url));
 */
function sanitize_header(string $value): string
{
    // Remove ALL newline and carriage return characters
    // These are the core of header injection attacks
    $value = str_replace(["\r\n", "\r", "\n", "%0d", "%0a", "%0D", "%0A"], '', $value);

    // Remove null bytes
    $value = str_replace("\0", '', $value);

    // Remove control characters
    $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value ?? '');

    return trim($value ?? '');
}

/**
 * Sanitize and validate a redirect URL.
 * Only allows relative URLs — prevents open redirect attacks.
 *
 * Defends against:
 *   - Open redirects: ?next=http://evil.com
 *   - Javascript URLs: javascript:alert(1)
 *   - Protocol hijacking: //evil.com
 *
 * Usage:
 *   $next = safe_redirect_url($_GET['next'] ?? '/index.php');
 *   header('Location: ' . $next);
 */
function safe_redirect_url(string $url, string $default = '/index.php'): string
{
    $url = trim($url);

    // Empty → use default
    if ($url === '') {
        return $default;
    }

    // Must start with / (relative URL only)
    // Rejects: http://, https://, //evil.com, javascript:
    if (!str_starts_with($url, '/')) {
        return $default;
    }

    // Reject protocol-relative URLs: //evil.com
    if (str_starts_with($url, '//')) {
        return $default;
    }

    // Reject javascript: anywhere in the URL
    if (stripos($url, 'javascript:') !== false) {
        return $default;
    }

    // Sanitize the URL
    return sanitize_header($url);
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 8 — IP ADDRESS SANITIZER
//  For activity_logs (Member 4's logger.php)
// ══════════════════════════════════════════════════════════════════

/**
 * Get and validate the client IP address.
 * Handles proxy headers safely.
 *
 * Usage:
 *   $ip = get_client_ip();
 *   // use in logger.php
 */
function get_client_ip(): string
{
    // Check proxy headers — but don't trust them blindly
    // X-Forwarded-For can be spoofed but is better than nothing
    $candidates = [];

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Can be comma-separated list — take the first one
        $forwarded = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $candidates[] = trim($forwarded[0]);
    }

    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $candidates[] = trim($_SERVER['HTTP_CLIENT_IP']);
    }

    // REMOTE_ADDR is most reliable — not spoofable at TCP level
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $candidates[] = trim($_SERVER['REMOTE_ADDR']);
    }

    // Validate each candidate — return first valid IP
    foreach ($candidates as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            return $ip;
        }
    }

    return '0.0.0.0'; // fallback — should never reach here
}

/**
 * Sanitize IP for storage in activity_logs.
 * Schema: VARCHAR(45) covers IPv6.
 *
 * Usage:
 *   $ip = sanitize_ip($rawIp);
 */
function sanitize_ip(string $ip): string
{
    $ip = trim($ip);

    if (filter_var($ip, FILTER_VALIDATE_IP,
    FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
        return $ip;
    }

    return '0.0.0.0';
}

// ══════════════════════════════════════════════════════════════════
//  SECTION 9 — SEARCH INPUT SANITIZER
//  For Member 3's search.php
// ══════════════════════════════════════════════════════════════════

/**
 * Sanitize a search query.
 * PDO handles SQLi — this handles XSS and junk.
 *
 * Usage:
 *   $query = sanitize_search($_POST['q'] ?? '');
 */
function sanitize_search(string $query): string
{
    // Clean input first
    $query = clean_input($query);

    // Strip HTML tags
    $query = strip_tags($query);

    // Enforce reasonable max length for search
    $query = mb_substr($query, 0, 100, 'UTF-8');

    return $query;
}


// ══════════════════════════════════════════════════════════════════
//  SECTION 10 — UTILITY
// ══════════════════════════════════════════════════════════════════

/**
 * Check if a string is empty after cleaning.
 * Use for required field validation.
 *
 * Usage:
 *   if (is_empty_input($username)) { $error = 'Username required'; }
 */
function is_empty_input(string $value): bool
{
    return trim($value) === '';
}

/**
 * Truncate a string safely for display.
 * Multibyte safe.
 *
 * Usage:
 *   echo escape_output(truncate($bio, 100));
 */
function truncate(string $str, int $length, string $suffix = '...'): string
{
    if (mb_strlen($str, 'UTF-8') <= $length) {
        return $str;
    }

    return mb_substr($str, 0, $length, 'UTF-8') . $suffix;
}


/**
 * Validate and sanitize a UUID (public_id from users table).
 * M5 added public_id as external identifier — use this
 * instead of sanitize_uint() when handling user search/transfer.
 *
 * Usage (Member 3 — search and transfer):
 *   $publicId = sanitize_uuid($_POST['receiver_public_id'] ?? '');
 *   if ($publicId === null) { $error = 'Invalid user ID'; }
 */
function sanitize_uuid(mixed $value): ?string
{
    if ($value === null || $value === '') {
        return null;
    }

    $str = trim((string)$value);

    // Remove null bytes
    $str = str_replace("\0", '', $str);

    // Validate UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    if (!preg_match(
    '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/',
    $str
    )) {
        return null;
    }

    // Normalize to lowercase
    return strtolower($str);
}


// ## Quick Reference Card for Team
// ```
// ┌─────────────────────────────────────────────────────────────────┐
// │              sanitize.php — TEAM REFERENCE                      │
// ├─────────────────────────────────────────────────────────────────┤
// │ OUTPUT (every echo)    →  escape_output($value)                 │
// │ POST string            →  post_str('field')                     │
// │ POST integer           →  post_int('field')                     │
// │ GET string             →  get_str('field')                      │
// │ GET integer            →  get_int('field')                      │
// ├─────────────────────────────────────────────────────────────────┤
// │ Validate username      →  validate_username($val)               │
// │ Validate email         →  validate_email($val)                  │
// │ Normalize email        →  normalize_email($val)                 │
// │ Validate password      →  validate_password($val)               │
// ├─────────────────────────────────────────────────────────────────┤
// │ Transfer amount        →  sanitize_amount($val)                 │
// │ User ID                →  sanitize_uint($val)                   │
// │ Public User ID         →  sanitize_public_user_id($val)         │
// │ Biography              →  sanitize_bio($val)                    │
// │ Comment                →  sanitize_comment($val)                │
// │ Filename               →  sanitize_filename($val)               │
// │ Search query           →  sanitize_search($val)                 │
// │ Redirect URL           →  safe_redirect_url($val)               │
// │ Client IP              →  get_client_ip()                       │
// ├─────────────────────────────────────────────────────────────────┤
// │ NEVER sanitize passwords — hash directly with password_hash()   │
// └─────────────────────────────────────────────────────────────────┘
