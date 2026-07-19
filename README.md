# DSU init NOP Patcher

This is a static GitHub Pages build. It uses only browser JavaScript: the
selected `init` never leaves the browser, and the downloaded file is generated
locally.

It patches only the verified DSU AVB branch:

```text
20 0D 00 36 -> 1F 20 03 D5
```

It does not rename or otherwise modify the DSU AVB marker path.

## Publish with GitHub Pages

1. Create a new GitHub repository.
2. Upload the contents of this directory to the repository root.
3. Open `Settings` -> `Pages`.
4. Set the source to `Deploy from a branch`, choose `main`, then choose `/(root)`.
5. Save and open the generated Pages URL.

No backend, Actions workflow, API key, or server process is required.
