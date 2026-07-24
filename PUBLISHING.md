# Publishing guide

Steps to publish `sql-injections` to the npm registry.

## 1. Prerequisites

- An account at https://www.npmjs.com
- Node.js >= 18 and npm installed (`node -v`, `npm -v`)
- The name `sql-injections` must be available or owned by you. Check it:

  ```bash
  npm view sql-injections
  ```

  - If it returns data for a package that is **not** yours, the name is taken:
    change `name` in `package.json` (e.g. to a scoped name
    `@your-user/sql-injections`).
  - If it returns `404`, the name is free.

## 2. Before publishing

```bash
# 1. Install (no dependencies, but it validates package.json)
npm install

# 2. Run the tests — they also run automatically via "prepublishOnly"
npm test

# 3. Review EXACTLY which files will be uploaded
npm pack --dry-run
```

Only these should be packed: `sql-injections.js`, `lib/`, `README.md`,
`LICENSE`, `CHANGELOG.md` and `package.json` (controlled by the `files` field).

## 3. Versioning (SemVer)

Use `npm version` to bump the version and create the git commit and tag:

```bash
npm version patch   # 1.0.0 -> 1.0.1  (fixes)
npm version minor   # 1.0.0 -> 1.1.0  (new backward-compatible features)
npm version major   # 1.0.0 -> 2.0.0  (breaking changes)
```

The initial version is already `1.0.0`, so you can skip this step for the first
publish.

## 4. Log in and publish

```bash
# Log in (opens the browser for 2FA if enabled)
npm login

# Verify who you are
npm whoami

# Publish
npm publish
```

> If you use a scoped name (`@your-user/sql-injections`) and want it public, add
> this the first time:
> ```bash
> npm publish --access public
> ```

### Publishing with a token (CI / no interactive login)

If you use an access token instead of `npm login`, use an **Automation** or a
**Granular** token with **read and write** permission (a read-only token causes
a `403`). Configure it locally with:

```bash
npm config set //registry.npmjs.org/:_authToken=YOUR_TOKEN
```

Automation / granular write tokens bypass the interactive 2FA prompt.

## 5. Verify

```bash
npm view sql-injections
```

Then test the install in a clean folder:

```bash
mkdir /tmp/test && cd /tmp/test && npm init -y
npm install sql-injections
node -e "console.log(require('sql-injections').hasSql(\"' OR 1=1 --\"))"  # true
```

## 6. Publishing later updates

1. Update the code and add an entry to `CHANGELOG.md`.
2. `npm test`
3. `npm version patch|minor|major`
4. `npm publish`
5. `git push && git push --tags`

## Notes

- **2FA:** enabling two-factor authentication on your npm account is recommended
  (`Account → Two-Factor Authentication`).
- **Undoing a publish:** you can only `npm unpublish` within the first 72 hours
  and under certain conditions. Publish carefully.
- **Contact email:** if you want a public email for reports, add it in
  `package.json` under `bugs.email` or `author` (it will be visible on npm).
- **Never share your token** in chats, commits, or screenshots. If a token is
  ever exposed, revoke it immediately from npmjs.com → Access Tokens.
