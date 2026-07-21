# DSU init Patcher

This is a static GitHub Pages build. It uses only browser JavaScript: the
selected `init` never leaves the browser, and the downloaded file is generated
locally.

It patches only the verified DSU AVB branch:

```text
20 0D 00 36 -> 1F 20 03 D5
```

It does not rename or otherwise modify the DSU AVB marker path.
