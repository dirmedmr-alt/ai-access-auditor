// French and Arabic for the native popups, alerts, notifications and menus.
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
        if let p = pref, ["en", "fr", "ar"].contains(p) { lang = p; return }
        lang = ["fr", "ar"].contains(systemLang) ? systemLang : "en"
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
    ]
}

/// Translate an English text (and fill in its %@ / %d parts).
func L(_ en: String, _ args: CVarArg...) -> String {
    let f = I18n.lang == "en" ? en : (I18n.table[en]?[I18n.lang == "fr" ? 0 : 1] ?? en)
    if args.isEmpty { return f }
    // in Arabic, keep names and paths ("Claude Code", "~/projects") in their own left-to-right order
    let a: [CVarArg] = I18n.rtl ? args.map { $0 is String ? "\u{2068}\($0)\u{2069}" : $0 } : args
    return String(format: f, arguments: a)
}
