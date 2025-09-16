## 🧪 **Case 1: Repo has a clean go.mod**   ------------- SUCESS

* **Repo contents:**

  * Proper `go.mod` with all imports listed.
  * All `.go` files compile.
* **Expected outcome:**

  * Script parses imports → finds nothing missing.
  * Syft confirms versions match.
  * `go.mod` unchanged.
* **Why test?** Baseline sanity check — no false positives.

---

## 🧪 **Case 2: Repo has go.mod but missing some imports** ------------- SUCESS

* **Repo contents:**

  * `go.mod` exists but **omits one or two imports** that are used in `.go` files.
  * Example: file uses `github.com/pkg/errors` but `go.mod` doesn’t list it.
* **Expected outcome:**

  * Handler detects missing import.
  * Looks up version from Syft.
  * Adds it to `go.mod`.
  * Logs the recovery action.
* **Without script:**

  * `go mod tidy` would add it silently, but with *latest version*.
* **Why test?** Proves handler’s value in preserving “real” dependency versions.

---

## 🧪 **Case 3: Repo has no go.mod**

* **Repo contents:**

  * Pure `.go` source files.
  * Lots of imports (stdlib + external).
* **Expected outcome:**

  * Handler generates a brand-new `go.mod`.
  * Populates with all external imports + versions from Syft.
  * Leaves stdlib out.
* **Without script:**

  * `go mod init` + `go mod tidy` would create `go.mod` but versions may mismatch reality.
* **Why test?** Validates “recovery mode” works even when `go.mod` is missing.

---

## 🧪 **Case 4: Repo has corrupted go.mod**

* **Repo contents:**

  * `go.mod` exists but malformed (syntax error, bad path, invalid versions).
* **Expected outcome:**

  * Script ignores broken `go.mod`.
  * Rebuilds from `.go` imports + Syft.
* **Without script:**

  * `go mod tidy` would just error out.
* **Why test?** Shows robustness against broken metadata.

---

## 🧪 **Case 5: Repo imports only stdlib**

* **Repo contents:**

  * All `.go` files only import stdlib packages (`fmt`, `os`, `net/http`, etc).
* **Expected outcome:**

  * Handler finds no external imports.
  * Either generates minimal `go.mod` (module name + Go version) or leaves it as-is.
* **Without script:**

  * `go mod tidy` does the same.
* **Why test?** Validates stdlib skipping logic.

---

## 🧪 **Case 6: Repo with replaced/indirect modules**

* **Repo contents:**

  * `go.mod` has `replace` directives or indirect deps.
  * Example: `replace github.com/foo/bar => ../local/bar`.
* **Expected outcome:**

  * Handler respects existing `replace`/indirects if valid.
  * Only adds truly missing imports.
* **Without script:**

  * `go mod tidy` might re-resolve and override things.
* **Why test?** Ensures handler doesn’t break custom dependency setups.

---

## 🧪 **Case 7: Repo with vendored dependencies**

* **Repo contents:**

  * Has `vendor/` directory checked in.
* **Expected outcome:**

  * Handler still parses imports normally.
  * Syft may detect versions from vendor.
  * `go.mod` updated correctly.
* **Without script:**

  * `go mod tidy` ignores `vendor/` unless `-mod=vendor` is used.
* **Why test?** Validates vendor-handling.

---

✅ This covers the full spectrum:

* Good → Missing → Absent → Broken → Pure stdlib → Custom → Vendor.

---

👉 Do you want me to prepare **sample repos/snippets for each case** so you can actually run the handler against them, or just keep this as a theoretical checklist?
