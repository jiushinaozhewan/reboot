//! Build script for reboot-agent
//!
//! Embeds Windows manifest for UTF-8 support and DPI awareness

fn main() {
    // Set Windows 7 as minimum version for compatibility
    #[cfg(windows)]
    {
        // _WIN32_WINNT_WIN7 = 0x0601
        println!("cargo:rustc-env=WINVER=0x0601");
        println!("cargo:rustc-env=_WIN32_WINNT=0x0601");
    }

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();

        // Set application manifest for:
        // - UTF-8 code page (required for Chinese text in dialogs)
        // - DPI awareness (crisp text rendering)
        // - Visual styles (modern look)
        // - Admin privileges (required for shutdown commands)
        res.set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="*"
    name="RebootAgent"
    type="win32"/>
  <description>Remote Power Management Agent</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#,
        );

        // Set application icon (if available)
        // res.set_icon("resources/icon.ico");

        if let Err(e) = res.compile() {
            eprintln!("Failed to compile resources: {}", e);
        }
    }
}
