---
title: WSL2 Firefox Wayland Issue
description: Workaround and fixes regarding the issue
categories:
 - Blog
 - Tech
tags:
- wsl2
- linux
- blog
---

## How it Started 
When I updated my WSL2 and Kali Linux Packages. Noticed that the interface of my firefox had changed.

## Understanding the Problem
WSL2 (Windows Subsystem for Linux 2) provides a Linux kernel and allows users to run a full Linux distribution on Windows. However, with newer versions of WSL2, Wayland has been the default graphical server protocol. **Since WSL2 doesn't have full native support for Wayland**, these issues might occur:

- Scrolling problems on web pages (does not go all the way to the bottom or the top, scrolling feels "jaggy")
- Cannot press menu buttons, nothing shows up upon pressing eg. Downloads. (had to shift + click instead to open something) 
- GUI not rendering properly

## Solution
To fix these issues, we'll force Firefox to use **X11**, an older but more widely supported protocol for graphical application.

```bash
export MOZ_ENABLE_WAYLAND=0
```

This will disable Wayland and force Firefox to use X11 instead.

## Referrence
- [https://www.reddit.com/r/wsl2/comments/1fyxfk1/firefox_not_working_properly_on_wsl2/](https://www.reddit.com/r/wsl2/comments/1fyxfk1/firefox_not_working_properly_on_wsl2/)
- [https://github.com/microsoft/wslg/issues/1119](https://github.com/microsoft/wslg/issues/1119)
