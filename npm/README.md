# pkgscope npm launcher

This package is the thin npm/npx launcher for the native `pkgscope` binary. It selects an exact-version platform package (`@pirasan023/pkgscope-darwin-arm64` or `@pirasan023/pkgscope-darwin-x64`), validates the version, and starts the binary with an argument array and `shell: false`. The TUI can run a package-manager-native uninstall only after showing the command and receiving an exact typed confirmation.

No install script downloads executables from the network. npm installs the platform package through `optionalDependencies` from the registry. Unsupported platforms and missing optional dependencies produce explicit errors.

This project was created with substantial assistance from generative AI. Use it entirely at your own risk. The uninstall feature can remove software or related data; review the displayed command before confirming. The software is provided without warranty, and the authors, contributors, and AI service providers accept no liability to the maximum extent permitted by law. The MIT License's “AS IS” terms apply.

See the main repository for CLI documentation and security details.
