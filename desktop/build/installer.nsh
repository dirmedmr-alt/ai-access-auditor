; Included by electron-builder in the Windows installers (nsis.include defaults to build/installer.nsh).
; An ARM-only installer run on an Intel/AMD PC would otherwise "succeed" without copying the app
; (electron-builder only extracts the files matching the PC), leaving a shortcut to a missing program.
!macro customInit
  !ifdef APP_ARM64
    !ifndef APP_64
      ${IfNot} ${IsNativeARM64}
        MessageBox MB_OK|MB_ICONSTOP "This installer is for ARM PCs, such as Snapdragon laptops. This PC needs the Windows (x64) version from the website.$\n$\nCe programme d'installation est pour les PC ARM, comme les portables Snapdragon. Ce PC a besoin de la version Windows (x64) du site.$\n$\nهذا المثبّت مخصّص لأجهزة ARM مثل الحواسيب المحمولة بمعالج Snapdragon. يحتاج هذا الجهاز إلى نسخة Windows (x64) من الموقع." /SD IDOK
        SetErrorLevel 2
        Quit
      ${EndIf}
    !endif
  !endif
!macroend
