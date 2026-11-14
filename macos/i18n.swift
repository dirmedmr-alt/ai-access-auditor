// French, Arabic and Chinese for the native popups, alerts, notifications and menus.
// Keys are the English text exactly as used in main.swift / prompt.swift; %@ (text) and %d (number) mark
// the parts that change. The language is the one chosen in the app (Setup → Language), saved in
// ~/.ai-access-audit/settings.json; "auto" follows the Mac's language.
import Foundation

enum I18n {
    static var lang = "en"
    static var rtl: Bool { lang == "ar" }

    /// The Mac's own language as a two-letter code (passed to the web page too).
    static var systemLang: String { String((Locale.preferredLanguages.first ?? "en").prefix(2)).lowercased() }

    static func set(_ pref: String?) {
        if let p = pref, ["en", "fr", "ar", "zh"].contains(p) { lang = p; return }
        lang = ["fr", "ar", "zh"].contains(systemLang) ? systemLang : "en"
    }

    static func load() {
        let dir = ProcessInfo.processInfo.environment["AUDIT_DATA_DIR"] ?? (NSHomeDirectory() + "/.ai-access-audit")
        let url = URL(fileURLWithPath: dir + "/settings.json")
        let json = (try? Data(contentsOf: url)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        set(json?["lang"] as? String)
    }

    /// What the agent wants to do ("run a command"), as it fits after "wants to".
    static func action(_ en: String) -> String {
        if lang == "en" { return en }
        if lang == "zh" { return zh[en] ?? (en.hasPrefix("use ") ? "使用 " + en.dropFirst(4) : en) }
        if let t = table[en] { return t[lang == "fr" ? 0 : 1] }
        if en.hasPrefix("use ") { return (lang == "fr" ? "utiliser " : "استخدام ") + en.dropFirst(4) }
        return en
    }

    static let table: [String: [String]] = [
        // gate popup
        "%@ wants to %@": ["%@ veut %@", "يريد %@ %@"],
        "run a command": ["exécuter une commande", "تشغيل أمر"],
        "change a file": ["modifier un fichier", "تغيير ملف"],
        "change files": ["modifier des fichiers", "تغيير ملفات"],
        "write a file": ["écrire un fichier", "كتابة ملف"],
        "read a file": ["lire un fichier", "قراءة ملف"],
        "open a web page": ["ouvrir une page web", "فتح صفحة ويب"],
        "search the web": ["chercher sur le web", "البحث في الويب"],
        "Tool: %@": ["Outil : %@", "الأداة: %@"],
        "Tool: %@ · in %@": ["Outil : %@ · dans %@", "الأداة: %@ · في %@"],
        "%@ is paused until you decide. You can take back this decision later under Decisions.":
            ["%@ est en pause jusqu’à votre décision. Vous pourrez revenir sur ce choix dans Décisions.",
             "%@ متوقف حتى تقرر. يمكنك التراجع عن هذا القرار لاحقًا من «القرارات»."],
        "Just this once": ["Juste cette fois", "هذه المرة فقط"],
        "Always (don't ask again)": ["Toujours (ne plus demander)", "دائمًا (لا تسأل مجددًا)"],
        "Allow": ["Autoriser", "سماح"],
        "Deny": ["Refuser", "رفض"],
        " HIGH RISK ": [" RISQUE ÉLEVÉ ", " خطورة عالية "],
        " MEDIUM RISK ": [" RISQUE MOYEN ", " خطورة متوسطة "],
        " LOW RISK ": [" RISQUE FAIBLE ", " خطورة منخفضة "],

        // new access popup
        "New AI agent on this Mac: %@": ["Nouvel agent IA sur ce Mac : %@", "وكيل ذكاء اصطناعي جديد على هذا الجهاز: %@"],
        "%@ got new access": ["%@ a obtenu un nouvel accès", "حصل %@ على صلاحية جديدة"],
        "\"Stop it\" ends the program now. \"Always\" lets this app send data without asking again (undo it under Decisions).":
            ["« L’arrêter » ferme le programme maintenant. « Toujours » laisse cette app envoyer des données sans redemander (annulable dans Décisions).",
             "«إيقافه» يُنهي البرنامج الآن. «دائمًا» يسمح لهذا التطبيق بإرسال البيانات دون سؤال مجددًا (يمكن التراجع من «القرارات»)."],
        "\"Stop it\" ends the process now. \"Let it run\" can also be limited to 1 hour, 1 day or 7 days.":
            ["« L’arrêter » met fin au processus maintenant. « Le laisser tourner » peut aussi être limité à 1 heure, 1 jour ou 7 jours.",
             "«إيقافه» يُنهي العملية الآن. ويمكن تحديد «تركه يعمل» بساعة أو يوم أو 7 أيام."],
        "Remove takes the access away now (a backup is saved, so you can undo it).":
            ["Retirer supprime l’accès maintenant (une sauvegarde est faite, vous pourrez annuler).",
             "«إزالة» تسحب الصلاحية الآن (تُحفظ نسخة احتياطية، فيمكنك التراجع)."],
        "This one has to be removed by hand. Choose \"Review\" to see how.":
            ["Celui-ci doit être retiré à la main. Choisissez « Examiner » pour voir comment.",
             "يجب إزالة هذا يدويًا. اختر «مراجعة» لمعرفة الطريقة."],
        "Allow this time": ["Autoriser cette fois", "السماح هذه المرة"],
        "Always for this app": ["Toujours pour cette app", "دائمًا لهذا التطبيق"],
        "Until it ends": ["Jusqu’à ce qu’il se termine", "حتى ينتهي"],
        "For 1 hour": ["Pendant 1 heure", "لمدة ساعة"],
        "For 1 day": ["Pendant 1 jour", "لمدة يوم"],
        "For 7 days": ["Pendant 7 jours", "لمدة 7 أيام"],
        "Keep it": ["Le garder", "إبقاؤها"],
        "Keep for 1 hour": ["Garder 1 heure", "إبقاؤها ساعة"],
        "Keep for 1 day": ["Garder 1 jour", "إبقاؤها يومًا"],
        "Keep for 7 days": ["Garder 7 jours", "إبقاؤها 7 أيام"],
        "Let it run": ["Le laisser tourner", "تركه يعمل"],
        "Keep": ["Garder", "إبقاء"],
        "Stop it": ["L’arrêter", "إيقافه"],
        "Remove": ["Retirer", "إزالة"],
        "Review": ["Examiner", "مراجعة"],
        "Couldn't remove %@": ["Impossible de retirer %@", "تعذّرت إزالة %@"],
        "Open AI Access Auditor to try again.": ["Ouvrez AI Access Auditor pour réessayer.", "افتح AI Access Auditor للمحاولة مجددًا."],

        // new agent: offer Allow / Deny
        "AI agent installed": ["Agent IA installé", "وكيل ذكاء اصطناعي مثبّت"],
        "\"Ask before it acts\" adds a small hook (a backup is saved) so %@ asks you here before it runs commands or changes files. You can turn it off any time on the Overview.":
            ["« Demander avant d’agir » ajoute un petit hook (une sauvegarde est faite) pour que %@ vous demande ici avant d’exécuter des commandes ou de modifier des fichiers. Vous pouvez le désactiver à tout moment dans la Vue d’ensemble.",
             "«اسأل قبل التنفيذ» يضيف خطّافًا صغيرًا (تُحفظ نسخة احتياطية) ليسألك %@ هنا قبل تشغيل الأوامر أو تغيير الملفات. يمكنك إيقافه في أي وقت من «نظرة عامة»."],
        "Ask before it acts": ["Demander avant d’agir", "اسأل قبل التنفيذ"],
        "Not now": ["Plus tard", "ليس الآن"],
        "Couldn't turn it on": ["Impossible de l’activer", "تعذّر تفعيله"],
        "%@ will ask you here": ["%@ vous demandera ici", "سيسألك %@ هنا"],
        "Open AI Access Auditor and use the switch on the Overview.": ["Ouvrez AI Access Auditor et utilisez l’interrupteur dans la Vue d’ensemble.", "افتح AI Access Auditor واستخدم المفتاح في «نظرة عامة»."],
        "Ask before Claude Code acts?": ["Demander avant que Claude Code agisse ?", "اسأل قبل أن يتصرف Claude Code؟"],
        "Whenever Claude Code is about to ask for permission, this app pops up instead so you can Allow or Deny. This adds a hook to ~/.claude/settings.json (a backup is saved). If this app isn't running, Claude Code just asks the usual way.":
            ["Quand Claude Code s’apprête à demander une permission, cette app s’ouvre à la place pour Autoriser ou Refuser. Cela ajoute un hook à ~/.claude/settings.json (une sauvegarde est faite). Si cette app n’est pas ouverte, Claude Code demande comme d’habitude.",
             "كلما كان Claude Code على وشك طلب إذن، يظهر هذا التطبيق بدلًا من ذلك لتختار «سماح» أو «رفض». يضيف هذا خطّافًا إلى ‎~/.claude/settings.json (تُحفظ نسخة احتياطية). إذا لم يكن هذا التطبيق يعمل، يسأل Claude Code بالطريقة المعتادة."],
        "Turn On": ["Activer", "تفعيل"],
        "Cancel": ["Annuler", "إلغاء"],
        "Confirm": ["Confirmer", "تأكيد"],
        "Couldn't change the Claude Code gate": ["Impossible de modifier la protection de Claude Code", "تعذّر تغيير حماية Claude Code"],

        // notifications
        "%@ gained access": ["%@ a obtenu un accès", "حصل %@ على صلاحية"],
        "High risk": ["Risque élevé", "خطورة عالية"],
        "Medium": ["Moyen", "متوسطة"],
        "Low": ["Faible", "منخفضة"],
        "%d more new AI grants": ["%d autres nouveaux accès IA", "%d صلاحيات ذكاء اصطناعي جديدة أخرى"],
        "Open AI Access Auditor to review them.": ["Ouvrez AI Access Auditor pour les vérifier.", "افتح AI Access Auditor لمراجعتها."],
        "Access expired and was removed": ["Un accès a expiré et a été retiré", "انتهت صلاحية وصول وأُزيلت"],
        "%d grants expired and were removed": ["%d accès ont expiré et ont été retirés", "انتهت %d صلاحيات وأُزيلت"],

        // types of access (same words as in the app window)
        "Tool permission": ["Permission d’outil", "إذن أداة"],
        "Folder access": ["Accès à un dossier", "وصول إلى مجلد"],
        "Trusted folder": ["Dossier de confiance", "مجلد موثوق"],
        "Permission mode": ["Mode d’autorisation", "وضع الأذونات"],
        "MCP server": ["Serveur MCP", "خادم MCP"],
        "Capability": ["Fonctionnalité", "ميزة"],
        "Hooks": ["Hooks", "خطّافات (Hooks)"],
        "macOS privacy": ["Confidentialité macOS", "خصوصية macOS"],
        "Running agent": ["Agent en cours d’exécution", "وكيل قيد التشغيل"],
        "AI tool install": ["Installation d’outil IA", "تثبيت أداة ذكاء اصطناعي"],
        "Data upload": ["Envoi de données", "إرسال بيانات"],
        "Agent skill": ["Compétence d’agent", "مهارة وكيل"],
        "Inherited credential": ["Identifiant hérité", "صلاحية دخول موروثة"],
        "Admin rights": ["Droits d’administrateur", "صلاحيات المسؤول"],
        "Saved login": ["Connexion enregistrée", "تسجيل دخول محفوظ"],
        "Background agent": ["Agent en arrière-plan", "وكيل في الخلفية"],
        "Editor extension": ["Extension d’éditeur", "إضافة محرر"],
        "Browser extension": ["Extension de navigateur", "إضافة متصفح"],
        "Network exposure": ["Exposition réseau", "مكشوف على الشبكة"],
        "Exposed secret": ["Secret exposé", "مفتاح سري مكشوف"],
        "AI Access Auditor %@ is available": ["AI Access Auditor %@ est disponible", "AI Access Auditor %@ متاح"],
        "Open the download page to get it.": ["Ouvrez la page de téléchargement pour l’obtenir.", "افتح صفحة التنزيل للحصول عليه."],
        "Update available: %@…": ["Mise à jour disponible : %@…", "تحديث متاح: %@…"],
        "Secret in history": ["Secret dans l’historique", "مفتاح سري في السجل"],
        "Data sharing": ["Partage de données", "مشاركة البيانات"],

        // menu bar
        "%d new AI access grants": ["%d nouveaux accès IA", "%d صلاحيات ذكاء اصطناعي جديدة"],
        "1 new AI access grant": ["1 nouvel accès IA", "صلاحية ذكاء اصطناعي جديدة واحدة"],
        "No new AI access": ["Aucun nouvel accès IA", "لا صلاحيات ذكاء اصطناعي جديدة"],
        "Checking…": ["Vérification…", "جارٍ التحقق…"],
        "%d new grants since you last looked": ["%d nouveaux accès depuis votre dernière visite", "%d صلاحيات جديدة منذ آخر مرة نظرت فيها"],
        "1 new grant since you last looked": ["1 nouvel accès depuis votre dernière visite", "صلاحية جديدة واحدة منذ آخر مرة نظرت فيها"],
        "…and %d more": ["…et %d de plus", "…و%d أخرى"],
        "Mark All as Seen": ["Tout marquer comme vu", "تعليم الكل كمُشاهَد"],
        "%d grants · %d high-risk not reviewed": ["%d accès · %d à haut risque non vérifiés", "%d صلاحية · %d عالية الخطورة لم تُراجع"],
        "Checked %@": ["Vérifié %@", "آخر تحقق %@"],
        "Open AI Access Auditor": ["Ouvrir AI Access Auditor", "فتح AI Access Auditor"],
        "Check Now": ["Vérifier maintenant", "تحقق الآن"],
        "Decisions…": ["Décisions…", "القرارات…"],
        "Setup…": ["Configuration…", "الإعداد…"],
        "Ask Before Claude Code Acts": ["Demander avant que Claude Code agisse", "اسأل قبل أن يتصرف Claude Code"],
        "Open at Login": ["Ouvrir à la connexion", "الفتح عند تسجيل الدخول"],
        "Quit": ["Quitter", "إنهاء"],
        "AI Access Auditor %@ is ready to install": ["AI Access Auditor %@ est prêt à être installé", "AI Access Auditor %@ جاهز للتثبيت"],
        "Click to restart and update. It takes a few seconds.": ["Cliquez pour redémarrer et mettre à jour. Cela prend quelques secondes.", "انقر لإعادة التشغيل والتحديث. يستغرق ذلك بضع ثوانٍ."],
        "Restart to Update to %@": ["Redémarrer pour passer à la %@", "أعد التشغيل للتحديث إلى %@"],
        "Left behind": ["Laissé sur place", "بقايا"],
    ]

    /// Simplified Chinese, for the same texts (desktop/gen-strings.js copies it for Windows and Linux).
    static let zh: [String: String] = [
        "%@ wants to %@": "%@ 想要%@",
        "run a command": "运行一条命令",
        "change a file": "修改一个文件",
        "change files": "修改文件",
        "write a file": "写入一个文件",
        "read a file": "读取一个文件",
        "open a web page": "打开一个网页",
        "search the web": "搜索网络",
        "Tool: %@": "工具：%@",
        "Tool: %@ · in %@": "工具：%@ · 位于 %@",
        "%@ is paused until you decide. You can take back this decision later under Decisions.": "%@ 已暂停，等待你的决定。之后可以在“决定”中收回这个决定。",
        "Just this once": "仅此一次",
        "Always (don't ask again)": "始终（不再询问）",
        "Allow": "允许",
        "Deny": "拒绝",
        " HIGH RISK ": " 高风险 ",
        " MEDIUM RISK ": " 中风险 ",
        " LOW RISK ": " 低风险 ",
        "New AI agent on this Mac: %@": "这台 Mac 上的新 AI 代理：%@",
        "%@ got new access": "%@ 获得了新权限",
        "\"Stop it\" ends the program now. \"Always\" lets this app send data without asking again (undo it under Decisions).": "“停止”会立即结束该程序。“始终”让此应用以后不经询问发送数据（可在“决定”中撤销）。",
        "\"Stop it\" ends the process now. \"Let it run\" can also be limited to 1 hour, 1 day or 7 days.": "“停止”会立即结束该进程。“让它运行”也可以限制为 1 小时、1 天或 7 天。",
        "Remove takes the access away now (a backup is saved, so you can undo it).": "“移除”会立即收回该权限（会保存备份，因此可以撤销）。",
        "This one has to be removed by hand. Choose \"Review\" to see how.": "此项需要手动移除。选择“查看”了解方法。",
        "Allow this time": "本次允许",
        "Always for this app": "对此应用始终允许",
        "Until it ends": "直到结束",
        "For 1 hour": "1 小时",
        "For 1 day": "1 天",
        "For 7 days": "7 天",
        "Keep it": "保留",
        "Keep for 1 hour": "保留 1 小时",
        "Keep for 1 day": "保留 1 天",
        "Keep for 7 days": "保留 7 天",
        "Let it run": "让它运行",
        "Keep": "保留",
        "Stop it": "停止",
        "Remove": "移除",
        "Review": "查看",
        "Couldn't remove %@": "无法移除 %@",
        "Open AI Access Auditor to try again.": "打开 AI Access Auditor 重试。",
        "AI agent installed": "已安装 AI 代理",
        "\"Ask before it acts\" adds a small hook (a backup is saved) so %@ asks you here before it runs commands or changes files. You can turn it off any time on the Overview.": "“行动前先询问”会添加一个小钩子（会保存备份），让 %@ 在运行命令或修改文件前先在这里询问你。随时可以在概览中关闭。",
        "Ask before it acts": "行动前先询问",
        "Not now": "暂不",
        "Couldn't turn it on": "无法开启",
        "%@ will ask you here": "%@ 会在这里询问你",
        "Open AI Access Auditor and use the switch on the Overview.": "打开 AI Access Auditor，使用概览中的开关。",
        "Ask before Claude Code acts?": "在 Claude Code 行动前先询问？",
        "Whenever Claude Code is about to ask for permission, this app pops up instead so you can Allow or Deny. This adds a hook to ~/.claude/settings.json (a backup is saved). If this app isn't running, Claude Code just asks the usual way.": "每当 Claude Code 即将请求权限时，本应用会改为弹出窗口，让你选择允许或拒绝。这会在 ~/.claude/settings.json 中添加一个钩子（会保存备份）。如果本应用没有运行，Claude Code 会按平常的方式询问。",
        "Turn On": "开启",
        "Cancel": "取消",
        "Confirm": "确认",
        "Couldn't change the Claude Code gate": "无法更改 Claude Code 询问设置",
        "%@ gained access": "%@ 获得了权限",
        "High risk": "高风险",
        "Medium": "中",
        "Low": "低",
        "%d more new AI grants": "另有 %d 项新的 AI 授权",
        "Open AI Access Auditor to review them.": "打开 AI Access Auditor 进行审核。",
        "Access expired and was removed": "权限已过期并被移除",
        "%d grants expired and were removed": "%d 项授权已过期并被移除",
        "Tool permission": "工具权限",
        "Folder access": "文件夹访问",
        "Trusted folder": "受信任的文件夹",
        "Permission mode": "权限模式",
        "MCP server": "MCP 服务器",
        "Capability": "功能",
        "Hooks": "钩子",
        "macOS privacy": "macOS 隐私",
        "Running agent": "运行中的代理",
        "AI tool install": "AI 工具安装",
        "Data upload": "数据上传",
        "Agent skill": "代理技能",
        "Inherited credential": "继承的凭据",
        "Admin rights": "管理员权限",
        "Saved login": "已保存的登录",
        "Background agent": "后台代理",
        "Editor extension": "编辑器扩展",
        "Browser extension": "浏览器扩展",
        "Network exposure": "网络暴露",
        "Exposed secret": "暴露的密钥",
        "AI Access Auditor %@ is available": "AI Access Auditor %@ 已推出",
        "Open the download page to get it.": "打开下载页面获取。",
        "Update available: %@…": "有可用更新：%@…",
        "Secret in history": "历史中的密钥",
        "Data sharing": "数据共享",
        "%d new AI access grants": "%d 项新的 AI 权限",
        "1 new AI access grant": "1 项新的 AI 权限",
        "No new AI access": "没有新的 AI 权限",
        "Checking…": "正在检查…",
        "%d new grants since you last looked": "自上次查看以来新增 %d 项授权",
        "1 new grant since you last looked": "自上次查看以来新增 1 项授权",
        "…and %d more": "…另有 %d 项",
        "Mark All as Seen": "全部标为已查看",
        "%d grants · %d high-risk not reviewed": "%d 项授权 · %d 项高风险未审核",
        "Checked %@": "检查于 %@",
        "Open AI Access Auditor": "打开 AI Access Auditor",
        "Check Now": "立即检查",
        "Decisions…": "决定…",
        "Setup…": "设置…",
        "Ask Before Claude Code Acts": "在 Claude Code 行动前先询问",
        "Open at Login": "登录时打开",
        "Quit": "退出",
        "Left behind": "卸载残留",
        "AI Access Auditor %@ is ready to install": "AI Access Auditor %@ 已可安装",
        "Click to restart and update. It takes a few seconds.": "点击即可重启并更新，只需几秒钟。",
        "Restart to Update to %@": "重启并更新到 %@",
    ]
}

/// Translate an English text (and fill in its %@ / %d parts).
func L(_ en: String, _ args: CVarArg...) -> String {
    let f = I18n.lang == "en" ? en : I18n.lang == "zh" ? (I18n.zh[en] ?? en) : (I18n.table[en]?[I18n.lang == "fr" ? 0 : 1] ?? en)
    if args.isEmpty { return f }
    // in Arabic, keep names and paths ("Claude Code", "~/projects") in their own left-to-right order
    let a: [CVarArg] = I18n.rtl ? args.map { $0 is String ? "\u{2068}\($0)\u{2069}" : $0 } : args
    return String(format: f, arguments: a)
}
