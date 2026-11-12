// App translations (French, Arabic) for public/index.html.
// The page is written in English. This file translates what appears on screen: text, tooltips, placeholders,
// confirmations and toasts, including text added later by the page's code. User data is never translated:
// finding names (.ttl), the activity log, file paths and the inspector title stay as they are.
// To add a text: put [English exactly as shown, French, Arabic] in T, or a pattern in PATTERNS.
'use strict';
(function () {
  const nb = ' ';
  const T = [
    // ---------- sidebar & navigation ----------
    ['AI agent permissions', 'Permissions des agents IA', 'أذونات وكلاء الذكاء الاصطناعي'],
    ['Setup', 'Configuration', 'الإعداد'],
    ['Scanning…', 'Analyse…', 'جارٍ الفحص…'],
    ['Overview', 'Vue d’ensemble', 'نظرة عامة'],
    ['All grants', 'Tous les accès', 'كل الصلاحيات'],
    ['New', 'Nouveau', 'جديد'],
    ['Agents', 'Agents', 'الوكلاء'],
    ['Your account', 'Votre compte', 'حسابك'],
    ['More', 'Plus', 'المزيد'],
    ['Decisions', 'Décisions', 'القرارات'],
    ['Online accounts', 'Comptes en ligne', 'الحسابات على الإنترنت'],
    ['History & undo', 'Historique et annulation', 'السجل والتراجع'],
    ['Export report', 'Exporter un rapport', 'تصدير تقرير'],
    ['Save every grant as a page you can share or print', 'Enregistrer tous les accès dans une page à partager ou imprimer', 'حفظ كل الصلاحيات في صفحة يمكنك مشاركتها أو طباعتها'],
    ['Report saved in Downloads and opened in your browser.', 'Rapport enregistré dans Téléchargements et ouvert dans votre navigateur.', 'حُفظ التقرير في مجلد التنزيلات وفُتح في متصفحك.'],
    ['Report saved in the app\'s data folder and opened in your browser.', 'Rapport enregistré dans le dossier de données de l’app et ouvert dans votre navigateur.', 'حُفظ التقرير في مجلد بيانات التطبيق وفُتح في متصفحك.'],
    ['Rescan (⌘R)', 'Analyser à nouveau (⌘R)', 'إعادة الفحص (⌘R)'],

    // ---------- risk & status ----------
    ['High risk', 'Risque élevé', 'خطورة عالية'],
    ['High', 'Élevé', 'عالية'],
    ['Medium', 'Moyen', 'متوسطة'],
    ['Low', 'Faible', 'منخفضة'],
    ['All', 'Tous', 'الكل'],
    ['Reviewed', 'Vérifié', 'تمت مراجعته'],
    ['Not reviewed', 'Non vérifié', 'لم تتم مراجعته'],
    ['On', 'Activé', 'مفعّل'],
    ['Off', 'Désactivé', 'متوقف'],
    ['Select', 'Sélectionner', 'تحديد'],
    ['Select all shown', 'Tout sélectionner', 'تحديد كل المعروض'],
    ['Search grants', 'Rechercher', 'ابحث في الصلاحيات'],
    ['Hide reviewed', 'Masquer les accès vérifiés', 'إخفاء ما تمت مراجعته'],
    ['Close', 'Fermer', 'إغلاق'],
    ['Loading…', 'Chargement…', 'جارٍ التحميل…'],

    // ---------- types of access (category names) ----------
    ['Tool permission', 'Permission d’outil', 'إذن أداة'],
    ['Folder access', 'Accès à un dossier', 'وصول إلى مجلد'],
    ['Trusted folder', 'Dossier de confiance', 'مجلد موثوق'],
    ['Permission mode', 'Mode d’autorisation', 'وضع الأذونات'],
    ['MCP server', 'Serveur MCP', 'خادم MCP'],
    ['Capability', 'Fonctionnalité', 'ميزة'],
    ['Hooks', 'Hooks', 'خطّافات (Hooks)'],
    ['macOS privacy', 'Confidentialité macOS', 'خصوصية macOS'],
    ['Running agent', 'Agent en cours d’exécution', 'وكيل قيد التشغيل'],
    ['AI tool install', 'Installation d’outil IA', 'تثبيت أداة ذكاء اصطناعي'],
    ['AI agent installed', 'Agent IA installé', 'وكيل ذكاء اصطناعي مثبّت'],
    ['Data upload', 'Envoi de données', 'إرسال بيانات'],
    ['Agent skill', 'Compétence d’agent', 'مهارة وكيل'],
    ['Inherited credential', 'Identifiant hérité', 'صلاحية دخول موروثة'],
    ['Admin rights', 'Droits d’administrateur', 'صلاحيات المسؤول'],
    ['Saved login', 'Connexion enregistrée', 'تسجيل دخول محفوظ'],
    ['Background agent', 'Agent en arrière-plan', 'وكيل في الخلفية'],
    ['Editor extension', 'Extension d’éditeur', 'إضافة محرر'],
    ['Browser extension', 'Extension de navigateur', 'إضافة متصفح'],
    ['Network exposure', 'Exposition réseau', 'مكشوف على الشبكة'],
    ['Exposed secret', 'Secret exposé', 'مفتاح سري مكشوف'],
    ['Secret in history', 'Secret dans l’historique', 'مفتاح سري في السجل'],
    ['Data sharing', 'Partage de données', 'مشاركة البيانات'],

    // ---------- overview ----------
    ['safety score', 'score de sécurité', 'درجة الأمان'],
    ['Looking good', 'Tout va bien', 'الوضع جيد'],
    ['Worth a look', 'À vérifier', 'يستحق نظرة'],
    ['Needs attention', 'Attention requise', 'يحتاج إلى انتباه'],
    ['Only a few grants are left to review. Revoke what you don\'t use, and mark what you trust as reviewed.',
     'Il ne reste que quelques accès à vérifier. Retirez ce que vous n’utilisez pas et marquez comme vérifié ce qui est fiable.',
     'لم يتبقَّ إلا القليل من الصلاحيات للمراجعة. اسحب ما لا تستخدمه، وعلّم ما تثق به كمُراجَع.'],
    ['Some agents have more access than they might need. Revoke what you don\'t use, and mark what you trust as reviewed.',
     'Certains agents ont plus d’accès que nécessaire. Retirez ce que vous n’utilisez pas et marquez comme vérifié ce qui est fiable.',
     'لدى بعض الوكلاء صلاحيات أكثر مما يحتاجون. اسحب ما لا تستخدمه، وعلّم ما تثق به كمُراجَع.'],
    ['Agents have broad access you haven\'t reviewed yet. Revoke what you don\'t use, and mark what you trust as reviewed.',
     'Vos agents ont des accès étendus que vous n’avez pas encore vérifiés. Retirez ce que vous n’utilisez pas et marquez comme vérifié ce qui est fiable.',
     'لدى الوكلاء صلاحيات واسعة لم تراجعها بعد. اسحب ما لا تستخدمه، وعلّم ما تثق به كمُراجَع.'],
    ['See all grants', 'Voir tous les accès', 'عرض كل الصلاحيات'],
    ['To review', 'À vérifier', 'للمراجعة'],
    ['New since you last looked', 'Nouveau depuis votre dernière visite', 'جديد منذ آخر مرة نظرت فيها'],
    ['Mark all as seen', 'Tout marquer comme vu', 'تعليم الكل كمُشاهَد'],
    ['Protection', 'Protection', 'الحماية'],
    ['Live popups', 'Alertes en direct', 'تنبيهات فورية'],
    ['New access from any agent', 'Tout nouvel accès d’un agent', 'أي صلاحية جديدة من أي وكيل'],
    ['Ask before Claude Code acts', 'Demander avant que Claude Code agisse', 'اسأل قبل أن يتصرف Claude Code'],
    ['You approve each new action', 'Vous approuvez chaque nouvelle action', 'توافق على كل إجراء جديد'],
    ['Claude Code asks in its own window', 'Claude Code demande dans sa propre fenêtre', 'يسأل Claude Code في نافذته الخاصة'],
    ['Ask before Gemini CLI acts', 'Demander avant que Gemini CLI agisse', 'اسأل قبل أن يتصرف Gemini CLI'],
    ['When Gemini would act without asking', 'Quand Gemini agirait sans demander', 'عندما كان Gemini سيتصرف دون أن يسأل'],
    ['Gemini asks in its own window', 'Gemini demande dans sa propre fenêtre', 'يسأل Gemini في نافذته الخاصة'],
    ['Ask before Codex CLI acts', 'Demander avant que Codex CLI agisse', 'اسأل قبل أن يتصرف Codex CLI'],
    ['You approve each action here', 'Vous approuvez chaque action ici', 'توافق على كل إجراء من هنا'],
    ['Codex asks in its own window', 'Codex demande dans sa propre fenêtre', 'يسأل Codex في نافذته الخاصة'],
    ['macOS permissions', 'Autorisations macOS', 'أذونات macOS'],
    ['Screen, files, camera and more', 'Écran, fichiers, caméra et plus', 'الشاشة والملفات والكاميرا وغيرها'],
    ['Needs Full Disk Access', 'Nécessite l’accès complet au disque', 'يحتاج إلى «الوصول الكامل إلى القرص»'],
    ['Fix', 'Corriger', 'إصلاح'],
    ['Watch all apps', 'Surveiller toutes les apps', 'مراقبة كل التطبيقات'],
    ['Every app, not just AI', 'Toutes les apps, pas seulement l’IA', 'كل التطبيقات، لا الذكاء الاصطناعي فقط'],
    ['AI apps only', 'Apps d’IA uniquement', 'تطبيقات الذكاء الاصطناعي فقط'],
    ['Top risks', 'Principaux risques', 'أبرز المخاطر'],
    ['View all', 'Tout voir', 'عرض الكل'],
    ['Everything has been reviewed.', 'Tout a été vérifié.', 'تمت مراجعة كل شيء.'],
    ['By type', 'Par type', 'حسب النوع'],

    // ---------- lists ----------
    ['Every permission, folder, server and key given to an AI agent', 'Chaque permission, dossier, serveur et clé donnés à un agent IA', 'كل إذن ومجلد وخادم ومفتاح مُنح لوكيل ذكاء اصطناعي'],
    ['Access an agent gained after your last check. Revoke it, or keep it to mark it as seen.', 'Accès obtenus par un agent depuis votre dernière vérification. Retirez-les, ou gardez-les pour les marquer comme vus.', 'صلاحيات حصل عليها وكيل بعد آخر فحص لك. اسحبها، أو أبقِها لتعليمها كمُشاهَدة.'],
    ['Nothing matches these filters.', 'Rien ne correspond à ces filtres.', 'لا شيء يطابق هذه الفلاتر.'],
    ['Mark reviewed', 'Marquer comme vérifié', 'تعليم كمُراجَع'],
    ['Clear', 'Effacer', 'مسح'],

    // ---------- online accounts, decisions, history ----------
    ['These grants live in your online accounts, so they can\'t be scanned from your Mac. Check each one.', 'Ces accès sont dans vos comptes en ligne et ne peuvent pas être analysés depuis votre Mac. Vérifiez-les un par un.', 'هذه الصلاحيات موجودة في حساباتك على الإنترنت، فلا يمكن فحصها من جهازك. راجع كلًّا منها.'],
    ['Every Allow and Deny you gave in the popup. Change your mind any time.', 'Chaque Autoriser et Refuser donné dans la fenêtre. Changez d’avis quand vous voulez.', 'كل «سماح» و«رفض» اخترته في النافذة. يمكنك تغيير رأيك في أي وقت.'],
    ['Apps allowed to send data', 'Apps autorisées à envoyer des données', 'تطبيقات مسموح لها بإرسال البيانات'],
    ['Watch again', 'Surveiller à nouveau', 'المراقبة من جديد'],
    ['Claude Code requests', 'Demandes de Claude Code', 'طلبات Claude Code'],
    ['No decisions yet.', 'Aucune décision pour l’instant.', 'لا قرارات بعد.'],
    ['When Claude Code asks for something, your answer will show up here.', 'Quand Claude Code demande quelque chose, votre réponse apparaîtra ici.', 'عندما يطلب Claude Code شيئًا، ستظهر إجابتك هنا.'],
    ['Turn on', 'Activez', 'فعّل'],
    ['on the Overview, and your answers will show up here.', 'dans la Vue d’ensemble, et vos réponses apparaîtront ici.', 'في «نظرة عامة»، وستظهر إجاباتك هنا.'],
    ['Blocked', 'Bloqué', 'محظور'],
    ['Always allowed', 'Toujours autorisé', 'مسموح دائمًا'],
    ['Rule removed', 'Règle supprimée', 'أُزيلت القاعدة'],
    ['Allowed once', 'Autorisé une fois', 'سُمح مرة واحدة'],
    ['Denied once', 'Refusé une fois', 'رُفض مرة واحدة'],
    ['Revoke', 'Retirer', 'سحب'],
    ['Block from now on', 'Bloquer désormais', 'حظر من الآن'],
    ['Unblock', 'Débloquer', 'إلغاء الحظر'],
    ['Remove the saved rule; Claude Code will ask again', 'Supprimer la règle enregistrée ; Claude Code demandera à nouveau', 'إزالة القاعدة المحفوظة، وسيسأل Claude Code من جديد'],
    ['A backup is saved before every change. Restore one to put the access back.', 'Une sauvegarde est faite avant chaque modification. Restaurez-en une pour rétablir l’accès.', 'تُحفظ نسخة احتياطية قبل كل تغيير. استعد إحداها لإعادة الصلاحية.'],
    ['Backups', 'Sauvegardes', 'النسخ الاحتياطية'],
    ['Restore', 'Restaurer', 'استعادة'],
    ['No changes yet.', 'Aucune modification pour l’instant.', 'لا تغييرات بعد.'],
    ['Activity', 'Activité', 'النشاط'],
    ['Nothing yet.', 'Rien pour l’instant.', 'لا شيء بعد.'],

    // ---------- inspector ----------
    ['Type', 'Type', 'النوع'],
    ['Details', 'Détails', 'التفاصيل'],
    ['Stored in', 'Enregistré dans', 'محفوظ في'],
    ['Status', 'État', 'الحالة'],
    ['Revoke automatically', 'Retirer automatiquement', 'السحب تلقائيًا'],
    ['Never', 'Jamais', 'أبدًا'],
    ['1 hour', '1 heure', 'ساعة'],
    ['1 day', '1 jour', 'يوم'],
    ['7 days', '7 jours', '7 أيام'],
    ['30 days', '30 jours', '30 يومًا'],
    ['Stop it', 'L’arrêter', 'إيقافه'],
    ['Remove skill', 'Supprimer la compétence', 'إزالة المهارة'],
    ['Sign out (remove)', 'Se déconnecter (supprimer)', 'تسجيل الخروج (إزالة)'],
    ['Revoke access', 'Retirer l’accès', 'سحب الصلاحية'],
    ['Remove the secrets', 'Supprimer les secrets', 'إزالة المفاتيح السرية'],
    ['Turn it off', 'Le désactiver', 'إيقافه'],
    ['Remove these secrets from the session log?\n\nEach one is replaced with "[removed]". The rest of the conversation stays. This can\'t be undone, because a backup would keep the secrets.',
     `Supprimer ces secrets du journal de session${nb}?\n\nChacun est remplacé par «${nb}[removed]${nb}». Le reste de la conversation est conservé. C’est définitif, car une sauvegarde garderait les secrets.`,
     'إزالة هذه المفاتيح السرية من سجل الجلسة؟\n\nيُستبدل كل منها بـ«[removed]» وتبقى بقية المحادثة. لا يمكن التراجع عن ذلك، لأن النسخة الاحتياطية ستحتفظ بالمفاتيح.'],
    ['A key saved in an agent\'s session log', 'Une clé enregistrée dans le journal de session d’un agent', 'مفتاح محفوظ في سجل جلسة وكيل'],
    ['Agents keep a full log of every session on your computer. This one contains a key, token or password in plain text, which any program you run can read. Remove it from the log, and replace the key with the service too, because the agent may also have sent it to its AI provider.',
     'Les agents gardent un journal complet de chaque session sur votre ordinateur. Celui-ci contient une clé, un jeton ou un mot de passe en clair, que tout programme que vous lancez peut lire. Retirez-le du journal, et remplacez aussi la clé auprès du service, car l’agent a pu l’envoyer à son fournisseur d’IA.',
     'يحتفظ الوكلاء بسجل كامل لكل جلسة على جهازك. وهذا السجل يحتوي على مفتاح أو رمز أو كلمة مرور بنص واضح، يستطيع أي برنامج تشغّله قراءته. أزله من السجل، واستبدل المفتاح لدى الخدمة أيضًا، لأن الوكيل ربما أرسله إلى مزوّد الذكاء الاصطناعي.'],
    ['Data sent to the company that makes it', 'Des données envoyées à l’éditeur', 'بيانات تُرسل إلى الشركة المطوّرة'],
    ['This tool sends usage data to the company that makes it, or shares your sessions. Turn it off to keep that on your computer.',
     'Cet outil envoie des données d’utilisation à son éditeur, ou partage vos sessions. Désactivez-le pour garder cela sur votre ordinateur.',
     'ترسل هذه الأداة بيانات الاستخدام إلى الشركة المطوّرة لها، أو تشارك جلساتك. أوقفها لتبقى هذه البيانات على جهازك.'],
    ['Open settings', 'Ouvrir les réglages', 'فتح الإعدادات'],
    ['Change this one by hand.', 'Celui-ci se modifie à la main.', 'يجب تغيير هذا يدويًا.'],
    ['Always allow this app', 'Toujours autoriser cette app', 'السماح لهذا التطبيق دائمًا'],
    ['Mark as not reviewed', 'Marquer comme non vérifié', 'تعليم كغير مُراجَع'],
    ['Keep it — mark as reviewed', 'Le garder — marquer comme vérifié', 'إبقاؤه — تعليم كمُراجَع'],

    // ---------- plain-language explanations ----------
    ['Runs without asking', 'S’exécute sans demander', 'يعمل دون أن يسأل'],
    ['The agent can use this tool on its own, without asking you first. Wildcards like Bash(*) mean any shell command at all.', 'L’agent peut utiliser cet outil seul, sans vous demander. Un joker comme Bash(*) veut dire n’importe quelle commande shell.', 'يستطيع الوكيل استخدام هذه الأداة وحده دون أن يسألك أولًا. والرموز الشاملة مثل Bash(*) تعني أي أمر في الطرفية على الإطلاق.'],
    ['Can read and change files here', 'Peut lire et modifier les fichiers ici', 'يستطيع قراءة الملفات هنا وتغييرها'],
    ['The agent can open, edit and create files in this folder and everything inside it.', 'L’agent peut ouvrir, modifier et créer des fichiers dans ce dossier et tout son contenu.', 'يستطيع الوكيل فتح الملفات وتعديلها وإنشاءها في هذا المجلد وكل ما بداخله.'],
    ['Allowed to work in this folder', 'Autorisé à travailler dans ce dossier', 'مسموح له بالعمل في هذا المجلد'],
    ['You approved running the agent in this folder, which lets it load the project\'s settings, hooks and MCP servers.', 'Vous avez autorisé l’agent dans ce dossier, ce qui lui permet de charger les réglages, hooks et serveurs MCP du projet.', 'وافقت على تشغيل الوكيل في هذا المجلد، مما يتيح له تحميل إعدادات المشروع وخطّافاته وخوادم MCP الخاصة به.'],
    ['Changes how often you are asked', 'Change la fréquence des demandes', 'يغيّر عدد مرات سؤالك'],
    ['This mode lowers or removes the approval prompts that normally stop the agent before risky actions.', 'Ce mode réduit ou supprime les demandes d’approbation qui arrêtent normalement l’agent avant une action risquée.', 'هذا الوضع يقلّل أو يُلغي طلبات الموافقة التي توقف الوكيل عادةً قبل الإجراءات الخطرة.'],
    ['Connects the agent to another tool or service', 'Connecte l’agent à un autre outil ou service', 'يربط الوكيل بأداة أو خدمة أخرى'],
    ['An MCP server gives the agent extra abilities, such as reading your GitHub, files, databases or browser, often using a saved token.', 'Un serveur MCP donne des capacités supplémentaires à l’agent, comme lire votre GitHub, vos fichiers, bases de données ou navigateur, souvent avec un jeton enregistré.', 'يمنح خادم MCP الوكيلَ قدرات إضافية، مثل قراءة GitHub أو ملفاتك أو قواعد بياناتك أو متصفحك، غالبًا باستخدام رمز محفوظ.'],
    ['A feature switched on for the agent', 'Une fonctionnalité activée pour l’agent', 'ميزة مفعّلة للوكيل'],
    ['The agent can use this feature whenever it decides to.', 'L’agent peut utiliser cette fonctionnalité quand il le décide.', 'يستطيع الوكيل استخدام هذه الميزة متى قرر ذلك.'],
    ['Runs commands automatically', 'Exécute des commandes automatiquement', 'يشغّل أوامر تلقائيًا'],
    ['Hooks run shell commands whenever certain agent events happen, without asking.', 'Les hooks exécutent des commandes shell lors de certains événements de l’agent, sans demander.', 'تشغّل الخطّافات أوامر في الطرفية عند وقوع أحداث معيّنة للوكيل، دون أن تسأل.'],
    ['A system permission from macOS', 'Une autorisation système de macOS', 'إذن نظام من macOS'],
    ['macOS lets this app use a protected part of your Mac. Any agent running inside the app gets the same access.', 'macOS permet à cette app d’utiliser une partie protégée de votre Mac. Tout agent qui s’exécute dans l’app obtient le même accès.', 'يسمح macOS لهذا التطبيق باستخدام جزء محمي من جهازك، وأي وكيل يعمل داخل التطبيق يحصل على الصلاحية نفسها.'],
    ['Running right now with safety off', 'En cours d’exécution sans garde-fous', 'يعمل الآن دون حماية'],
    ['This agent is running at this moment with its approval prompts switched off, or as administrator. It can change files and run commands without asking. Stop it if you didn\'t start it this way on purpose.', 'Cet agent s’exécute en ce moment sans demandes d’approbation, ou en tant qu’administrateur. Il peut modifier des fichiers et lancer des commandes sans demander. Arrêtez-le si vous ne l’avez pas lancé ainsi volontairement.', 'هذا الوكيل يعمل الآن وطلبات الموافقة متوقفة، أو بصلاحيات المسؤول. يستطيع تغيير الملفات وتشغيل الأوامر دون أن يسأل. أوقفه إن لم تشغّله بهذه الطريقة عن قصد.'],
    ['An AI tool is being installed right now', 'Un outil IA est en cours d’installation', 'تُثبَّت أداة ذكاء اصطناعي الآن'],
    ['Someone ran the setup for an MCP server, agent skill or agent plugin on this Mac. Once it finishes, it usually gives your agents new abilities. Stop it if you didn\'t start it on purpose. If you keep it, you\'ll be asked about the access it adds.', 'Quelqu’un a lancé l’installation d’un serveur MCP, d’une compétence ou d’un plugin d’agent sur ce Mac. Une fois terminée, elle donne généralement de nouvelles capacités à vos agents. Arrêtez-la si vous ne l’avez pas lancée volontairement. Si vous la gardez, on vous demandera pour chaque accès ajouté.', 'شغّل أحدهم إعداد خادم MCP أو مهارة أو إضافة وكيل على هذا الجهاز. عند اكتماله يمنح وكلاءك عادةً قدرات جديدة. أوقفه إن لم تبدأه عن قصد، وإن أبقيته فستُسأل عن الصلاحيات التي يضيفها.'],
    ['An AI agent is installed', 'Un agent IA est installé', 'وكيل ذكاء اصطناعي مثبّت'],
    ['This AI tool is on your Mac. On its own that is no risk, but anything it can do (logins, folders, permissions) is listed under its name. If you no longer use it, uninstall it.', 'Cet outil IA est sur votre Mac. En soi, ce n’est pas un risque, mais tout ce qu’il peut faire (connexions, dossiers, permissions) est listé sous son nom. Si vous ne l’utilisez plus, désinstallez-le.', 'أداة الذكاء الاصطناعي هذه موجودة على جهازك. وجودها وحده ليس خطرًا، لكن كل ما تستطيع فعله (تسجيلات الدخول والمجلدات والأذونات) مُدرج تحت اسمها. إن لم تعد تستخدمها، فأزل تثبيتها.'],
    ['Sending data from your Mac', 'Envoie des données depuis votre Mac', 'يرسل بيانات من جهازك'],
    ['This program is sending data from your Mac to another computer on the internet. Programs that AI agents start (scripts, commands, MCP servers) are flagged from 64 KB, any other app from 20 MB. Check the files it has open. If you didn\'t expect it, stop it.', 'Ce programme envoie des données de votre Mac vers un autre ordinateur sur Internet. Les programmes lancés par des agents IA (scripts, commandes, serveurs MCP) sont signalés dès 64 Ko, les autres apps dès 20 Mo. Vérifiez les fichiers ouverts. Si vous ne vous y attendiez pas, arrêtez-le.', 'هذا البرنامج يرسل بيانات من جهازك إلى حاسوب آخر على الإنترنت. يُنبَّه عن البرامج التي يشغّلها وكلاء الذكاء الاصطناعي (سكربتات وأوامر وخوادم MCP) بدءًا من 64 كيلوبايت، وعن أي تطبيق آخر بدءًا من 20 ميغابايت. راجع الملفات المفتوحة لديه، وأوقفه إن لم تكن تتوقعه.'],
    ['Instructions the agent follows on its own', 'Des instructions que l’agent suit seul', 'تعليمات يتبعها الوكيل من تلقاء نفسه'],
    ['A skill is a folder of instructions, and often scripts, that the agent loads whenever it decides the skill fits the task. Scripts in it run with the same access as the agent.', 'Une compétence est un dossier d’instructions, souvent avec des scripts, que l’agent charge quand il juge qu’elle convient à la tâche. Ses scripts s’exécutent avec les mêmes accès que l’agent.', 'المهارة مجلد تعليمات، وغالبًا سكربتات، يحمّله الوكيل كلما رأى أنها تناسب المهمة. وتعمل السكربتات فيها بصلاحيات الوكيل نفسها.'],
    ['A login every agent can use', 'Une connexion que tout agent peut utiliser', 'تسجيل دخول يستطيع أي وكيل استخدامه'],
    ['You are logged in to this tool in your account, so any agent you run can use it as you. This works without the agent asking for anything.', 'Vous êtes connecté à cet outil dans votre compte, donc tout agent que vous lancez peut l’utiliser en votre nom, sans rien demander.', 'أنت مسجّل الدخول إلى هذه الأداة في حسابك، لذا يستطيع أي وكيل تشغّله استخدامها باسمك دون أن يطلب أي شيء.'],
    ['Administrator access', 'Accès administrateur', 'صلاحيات المسؤول'],
    ['Any program you run, including AI agents, can get full administrator rights on this Mac without asking for your password.', 'Tout programme que vous lancez, y compris les agents IA, peut obtenir les droits d’administrateur complets sur ce Mac sans demander votre mot de passe.', 'أي برنامج تشغّله، بما في ذلك وكلاء الذكاء الاصطناعي، يستطيع الحصول على صلاحيات المسؤول الكاملة على هذا الجهاز دون طلب كلمة السر.'],
    ['A saved login for an AI tool', 'Une connexion enregistrée pour un outil IA', 'تسجيل دخول محفوظ لأداة ذكاء اصطناعي'],
    ['This tool stays signed in using a token saved in your Keychain. Deleting it signs the tool out. The app never reads the secret itself.', 'Cet outil reste connecté grâce à un jeton enregistré dans votre Trousseau. Le supprimer déconnecte l’outil. L’app ne lit jamais le secret lui-même.', 'تبقى هذه الأداة مسجّلة الدخول برمز محفوظ في سلسلة المفاتيح. حذفه يسجّل خروج الأداة، والتطبيق لا يقرأ السر نفسه أبدًا.'],
    ['Starts without you', 'Démarre sans vous', 'يبدأ دون تدخّلك'],
    ['This job launches an AI tool automatically, at login or on a schedule, even when you aren\'t watching.', 'Cette tâche lance un outil IA automatiquement, à la connexion ou selon un horaire, même quand vous ne regardez pas.', 'هذه المهمة تشغّل أداة ذكاء اصطناعي تلقائيًا عند تسجيل الدخول أو وفق جدول، حتى وأنت لا تراقب.'],
    ['AI inside your code editor', 'De l’IA dans votre éditeur de code', 'ذكاء اصطناعي داخل محرر الأكواد'],
    ['This extension can read the code you have open. Agent-style extensions can also edit files and run terminal commands.', 'Cette extension peut lire le code ouvert. Les extensions de type agent peuvent aussi modifier des fichiers et lancer des commandes.', 'تستطيع هذه الإضافة قراءة الكود المفتوح لديك، والإضافات من نوع الوكيل تستطيع أيضًا تعديل الملفات وتشغيل أوامر الطرفية.'],
    ['AI inside your browser', 'De l’IA dans votre navigateur', 'ذكاء اصطناعي داخل متصفحك'],
    ['This extension can see the pages it runs on. With access to all sites, it can read and change anything you open, including email and banking.', 'Cette extension voit les pages sur lesquelles elle s’exécute. Avec l’accès à tous les sites, elle peut lire et modifier tout ce que vous ouvrez, y compris vos e-mails et votre banque.', 'ترى هذه الإضافة الصفحات التي تعمل عليها. ومع الوصول إلى كل المواقع، تستطيع قراءة وتغيير أي شيء تفتحه، بما في ذلك البريد والحسابات البنكية.'],
    ['Open to other devices', 'Ouvert aux autres appareils', 'مفتوح لأجهزة أخرى'],
    ['A local AI server is reachable from your network, so anyone on the same Wi-Fi could use it.', 'Un serveur IA local est accessible depuis votre réseau : n’importe qui sur le même Wi-Fi pourrait l’utiliser.', 'خادم ذكاء اصطناعي محلي يمكن الوصول إليه من شبكتك، فيستطيع أي شخص على شبكة Wi-Fi نفسها استخدامه.'],
    ['A key every agent can read', 'Une clé que tout agent peut lire', 'مفتاح يستطيع أي وكيل قراءته'],
    ['This key is loaded into every terminal, so any agent you run there can read and use it.', 'Cette clé est chargée dans chaque terminal, donc tout agent lancé dedans peut la lire et l’utiliser.', 'هذا المفتاح مُحمَّل في كل طرفية، فيستطيع أي وكيل تشغّله هناك قراءته واستخدامه.'],

    // ---------- toasts ----------
    ['All marked as seen', 'Tout est marqué comme vu', 'تم تعليم الكل كمُشاهَد'],
    ['Marked as reviewed', 'Marqué comme vérifié', 'تم التعليم كمُراجَع'],
    ['Marked as not reviewed', 'Marqué comme non vérifié', 'تم التعليم كغير مُراجَع'],
    ['Now watching every app for macOS permissions and background jobs', 'Surveillance de toutes les apps pour les autorisations macOS et les tâches en arrière-plan', 'تجري الآن مراقبة كل التطبيقات بحثًا عن أذونات macOS والمهام في الخلفية'],
    ['Watching AI apps only', 'Surveillance des apps d’IA uniquement', 'مراقبة تطبيقات الذكاء الاصطناعي فقط'],

    // ---------- confirmations ----------
    ['Let this app send data without asking from now on?\n\nYou can undo this under Decisions.', `Laisser cette app envoyer des données sans demander désormais${nb}?\n\nVous pourrez annuler ce choix dans Décisions.`, 'السماح لهذا التطبيق بإرسال البيانات دون سؤال من الآن؟\n\nيمكنك التراجع عن ذلك من «القرارات».'],
    ['Remove the rule this decision saved?\n\nClaude Code will ask you again next time.', `Supprimer la règle enregistrée par cette décision${nb}?\n\nClaude Code vous demandera à nouveau la prochaine fois.`, 'إزالة القاعدة التي حفظها هذا القرار؟\n\nسيسألك Claude Code من جديد في المرة القادمة.'],
    ['Block this from now on?\n\nClaude Code won\'t be allowed to do it, and won\'t ask. You can unblock it here later.', `Bloquer ceci désormais${nb}?\n\nClaude Code ne pourra plus le faire et ne demandera pas. Vous pourrez le débloquer ici plus tard.`, 'حظر هذا من الآن؟\n\nلن يُسمح لـ Claude Code بفعله ولن يسأل. يمكنك إلغاء الحظر من هنا لاحقًا.'],
    ['Unblock this?\n\nClaude Code will ask you again next time.', `Débloquer ceci${nb}?\n\nClaude Code vous demandera à nouveau la prochaine fois.`, 'إلغاء حظر هذا؟\n\nسيسألك Claude Code من جديد في المرة القادمة.'],
    ['Restore this file from its backup?\n\nThe current version is backed up first.', `Restaurer ce fichier depuis sa sauvegarde${nb}?\n\nLa version actuelle est d’abord sauvegardée.`, 'استعادة هذا الملف من نسخته الاحتياطية؟\n\nتُحفظ النسخة الحالية أولًا.'],
    ['Ask before Codex CLI acts?\n\nWhenever Codex is about to ask for permission, a window pops up here instead, so you can Allow or Deny. When Codex runs without asking (full-auto or bypass mode), you\'re asked here before each command, file change or MCP tool.\n\nThis adds hooks to ~/.codex/hooks.json (a backup is saved). One-time step: start Codex, type /hooks and trust them.',
     `Demander avant que Codex CLI agisse${nb}?\n\nQuand Codex s’apprête à demander une permission, une fenêtre s’ouvre ici à la place pour Autoriser ou Refuser. Quand Codex s’exécute sans demander (mode full-auto ou bypass), on vous demande ici avant chaque commande, modification de fichier ou outil MCP.\n\nCela ajoute des hooks à ~/.codex/hooks.json (une sauvegarde est faite). Étape unique${nb}: lancez Codex, tapez /hooks et faites-leur confiance.`,
     'اسأل قبل أن يتصرف Codex CLI؟\n\nكلما كان Codex على وشك طلب إذن، تظهر نافذة هنا بدلًا من ذلك لتختار «سماح» أو «رفض». وعندما يعمل Codex دون أن يسأل (وضع full-auto أو bypass)، تُسأل هنا قبل كل أمر أو تعديل ملف أو أداة MCP.\n\nيضيف هذا خطّافات إلى ‎~/.codex/hooks.json (تُحفظ نسخة احتياطية). خطوة لمرة واحدة: شغّل Codex واكتب ‎/hooks ثم ثق بها.'],
    ['Ask before Gemini CLI acts?\n\nWhen Gemini runs in YOLO mode (or auto-edit, for file changes) it acts without asking. With this on, a window pops up here first so you can Allow or Deny. In its normal mode Gemini keeps asking in its own window, so you\'re never asked twice.\n\nThis adds a hook to ~/.gemini/settings.json (a backup is saved).',
     `Demander avant que Gemini CLI agisse${nb}?\n\nEn mode YOLO (ou auto-edit pour les fichiers), Gemini agit sans demander. Avec cette option, une fenêtre s’ouvre ici d’abord pour Autoriser ou Refuser. En mode normal, Gemini continue de demander dans sa fenêtre, donc on ne vous demande jamais deux fois.\n\nCela ajoute un hook à ~/.gemini/settings.json (une sauvegarde est faite).`,
     'اسأل قبل أن يتصرف Gemini CLI؟\n\nعندما يعمل Gemini في وضع YOLO (أو التعديل التلقائي للملفات) فإنه يتصرف دون أن يسأل. مع تفعيل هذا، تظهر نافذة هنا أولًا لتختار «سماح» أو «رفض». وفي وضعه العادي يواصل Gemini السؤال في نافذته، فلن تُسأل مرتين.\n\nيضيف هذا خطّافًا إلى ‎~/.gemini/settings.json (تُحفظ نسخة احتياطية).'],
    ['Ask before Claude Code acts?\n\nWhenever Claude Code is about to ask for permission, a window pops up here so you can Allow or Deny. This adds a hook to ~/.claude/settings.json (a backup is saved). If this app isn\'t running, Claude Code asks the usual way.',
     `Demander avant que Claude Code agisse${nb}?\n\nQuand Claude Code s’apprête à demander une permission, une fenêtre s’ouvre ici pour Autoriser ou Refuser. Cela ajoute un hook à ~/.claude/settings.json (une sauvegarde est faite). Si cette app n’est pas ouverte, Claude Code demande comme d’habitude.`,
     'اسأل قبل أن يتصرف Claude Code؟\n\nكلما كان Claude Code على وشك طلب إذن، تظهر نافذة هنا لتختار «سماح» أو «رفض». يضيف هذا خطّافًا إلى ‎~/.claude/settings.json (تُحفظ نسخة احتياطية). إذا لم يكن هذا التطبيق يعمل، يسأل Claude Code بالطريقة المعتادة.'],

    // ---------- welcome / setup ----------
    ['Welcome', 'Bienvenue', 'مرحبًا'],
    ['Know what your AI agents can do', 'Sachez ce que vos agents IA peuvent faire', 'اعرف ما يستطيع وكلاء الذكاء الاصطناعي فعله'],
    ['AI Access Auditor finds every permission, folder, login and privilege your AI agents have, and lets you take any of it back. Let\'s switch on the protection. It takes about a minute.', 'AI Access Auditor trouve chaque permission, dossier, identifiant et privilège de vos agents IA, et vous permet de tout retirer. Activons la protection : cela prend environ une minute.', 'يكشف AI Access Auditor كل إذن ومجلد وتسجيل دخول وصلاحية لدى وكلاء الذكاء الاصطناعي، ويتيح لك سحب أيٍّ منها. لنفعّل الحماية، الأمر يستغرق دقيقة تقريبًا.'],
    ['Pops up the moment something changes', 'Vous alerte dès que quelque chose change', 'ينبّهك فور تغيّر أي شيء'],
    ['When any agent gains access or starts with its safety off, a window asks you to keep it or remove it.', 'Quand un agent obtient un accès ou démarre sans garde-fous, une fenêtre vous demande de le garder ou de le retirer.', 'عندما يحصل أي وكيل على صلاحية أو يبدأ دون حماية، تسألك نافذة هل تُبقيها أم تزيلها.'],
    ['Everything can be undone', 'Tout peut être annulé', 'يمكن التراجع عن كل شيء'],
    ['Each change is backed up first. Restore it from History at any time.', 'Chaque modification est d’abord sauvegardée. Restaurez-la depuis l’Historique à tout moment.', 'تُحفظ نسخة احتياطية قبل كل تغيير، ويمكنك استعادتها من «السجل» في أي وقت.'],
    ['Let it see macOS permissions', 'Lui permettre de voir les autorisations macOS', 'اسمح له برؤية أذونات macOS'],
    ['To check which apps can record your screen, control your Mac or read all your files, the app needs', 'Pour vérifier quelles apps peuvent enregistrer votre écran, contrôler votre Mac ou lire tous vos fichiers, l’app a besoin de', 'لمعرفة التطبيقات التي تستطيع تسجيل شاشتك أو التحكم في جهازك أو قراءة كل ملفاتك، يحتاج التطبيق إلى'],
    ['Full Disk Access', 'l’accès complet au disque', '«الوصول الكامل إلى القرص»'],
    ['. It only reads the permission list and never changes it without asking you.', '. Elle lit seulement la liste des autorisations et ne la modifie jamais sans vous demander.', '. فهو يقرأ قائمة الأذونات فقط ولا يغيّرها أبدًا دون أن يسألك.'],
    ['Granted. macOS permissions are included in every scan.', 'Accordé. Les autorisations macOS sont incluses dans chaque analyse.', 'تم المنح. أذونات macOS مشمولة في كل فحص.'],
    ['Not granted yet.', 'Pas encore accordé.', 'لم يُمنح بعد.'],
    ['Granted', 'Accordé', 'ممنوح'],
    ['Not yet', 'Pas encore', 'ليس بعد'],
    ['Click', 'Cliquez sur', 'انقر'],
    ['Open System Settings', 'Ouvrir Réglages Système', 'فتح إعدادات النظام'],
    ['and choose', 'et choisissez', 'واختر'],
    ['(or drag it in from the Finder window).', '(ou glissez-la depuis la fenêtre du Finder).', '(أو اسحبه من نافذة Finder).'],
    ['Turn it on, then click', 'Activez-la, puis cliquez sur', 'فعّله، ثم انقر'],
    ['Restart app', 'Redémarrer l’app', 'إعادة تشغيل التطبيق'],
    ['Show app in Finder', 'Afficher l’app dans le Finder', 'إظهار التطبيق في Finder'],
    ['Check again', 'Vérifier à nouveau', 'التحقق مجددًا'],
    ['Ask me before Claude Code acts', 'Me demander avant que Claude Code agisse', 'اسألني قبل أن يتصرف Claude Code'],
    ['Instead of Claude Code\'s own prompt, a window pops up here so you can', 'Au lieu de la demande de Claude Code, une fenêtre s’ouvre ici pour', 'بدلًا من سؤال Claude Code نفسه، تظهر نافذة هنا لتختار'],
    ['Allow', 'Autoriser', 'سماح'],
    ['or', 'ou', 'أو'],
    ['Deny', 'Refuser', 'رفض'],
    [', and change your mind later under Decisions. If this app isn\'t running, Claude Code asks the usual way.', ', et vous pouvez changer d’avis plus tard dans Décisions. Si cette app n’est pas ouverte, Claude Code demande comme d’habitude.', '، ويمكنك تغيير رأيك لاحقًا من «القرارات». إذا لم يكن هذا التطبيق يعمل، يسأل Claude Code بالطريقة المعتادة.'],
    ['Adds a small hook to ~/.claude/settings.json (a backup is saved).', 'Ajoute un petit hook à ~/.claude/settings.json (une sauvegarde est faite).', 'يضيف خطّافًا صغيرًا إلى ‎~/.claude/settings.json (تُحفظ نسخة احتياطية).'],
    ['Other agents don\'t offer a way to pause them, so for them you\'re told within seconds of any change instead.', 'Les autres agents ne peuvent pas être mis en pause : pour eux, vous êtes prévenu en quelques secondes de tout changement.', 'الوكلاء الآخرون لا يتيحون إيقافهم مؤقتًا، لذا تُبلَّغ خلال ثوانٍ بأي تغيير لديهم.'],
    ['Keep watching in the background', 'Continuer la surveillance en arrière-plan', 'المراقبة المستمرة في الخلفية'],
    ['The app lives in the menu bar. It keeps working after you close this window.', 'L’app vit dans la barre des menus. Elle continue de fonctionner quand vous fermez cette fenêtre.', 'يعيش التطبيق في شريط القوائم، ويواصل العمل بعد إغلاق هذه النافذة.'],
    ['Open at Login', 'Ouvrir à la connexion', 'الفتح عند تسجيل الدخول'],
    ['Check for updates', 'Rechercher les mises à jour', 'البحث عن تحديثات'],
    ['Privacy', 'Confidentialité', 'الخصوصية'],
    ['Secrets left in agents\' session logs, and data your tools send to the companies that make them.',
     'Les secrets restés dans les journaux de session des agents, et les données que vos outils envoient à leurs éditeurs.',
     'المفاتيح السرية المتبقية في سجلات جلسات الوكلاء، والبيانات التي ترسلها أدواتك إلى الشركات المطوّرة لها.'],
    ['Secrets in session history', 'Secrets dans l’historique des sessions', 'مفاتيح سرية في سجل الجلسات'],
    ['No keys or passwords found in agents\' session logs.', 'Aucune clé ni aucun mot de passe dans les journaux de session des agents.', 'لم يُعثر على مفاتيح أو كلمات مرور في سجلات جلسات الوكلاء.'],
    ['None of your tools sends usage data or shares sessions.', 'Aucun de vos outils n’envoie de données d’utilisation ni ne partage de sessions.', 'لا ترسل أي من أدواتك بيانات استخدام ولا تشارك جلسات.'],
    ['Training on your conversations', 'Entraînement sur vos conversations', 'التدريب على محادثاتك'],
    ['Whether the AI services use your chats to train their models. This can only be changed on their websites.',
     'Si les services d’IA utilisent vos conversations pour entraîner leurs modèles. Cela ne se change que sur leurs sites.',
     'هل تستخدم خدمات الذكاء الاصطناعي محادثاتك لتدريب نماذجها؟ لا يمكن تغيير ذلك إلا من مواقعها.'],
    ['Nothing found', 'Rien trouvé', 'لم يُعثر على شيء'],
    ['Review', 'Examiner', 'مراجعة'],
    ['Clear', 'Rien à signaler', 'سليم'],
    ['Once a day, asks GitHub whether a new version is out. Nothing about your computer is sent.',
     'Une fois par jour, demande à GitHub si une nouvelle version est sortie. Rien sur votre ordinateur n’est envoyé.',
     'مرة يوميًا، يسأل GitHub إن صدر إصدار جديد. لا يُرسَل أي شيء عن جهازك.'],
    ['Download', 'Télécharger', 'تنزيل'],
    ['Later', 'Plus tard', 'لاحقًا'],
    ['Also cover background jobs for every other app.', 'Couvrir aussi les tâches de fond de toutes les autres apps.', 'تغطية المهام الخلفية لكل التطبيقات الأخرى أيضًا.'],
    ['Now watching every app for background jobs', 'Surveillance des tâches de fond de toutes les apps', 'تتم الآن مراقبة المهام الخلفية لكل التطبيقات'],
    ['Starts quietly in the menu bar when you log in.', 'Démarre discrètement dans la barre des menus à la connexion.', 'يبدأ بهدوء في شريط القوائم عند تسجيل الدخول.'],
    ['Move the app to Applications first, so it can always be found at login.', 'Placez d’abord l’app dans Applications pour qu’elle soit toujours trouvée à la connexion.', 'انقل التطبيق إلى مجلد التطبيقات أولًا، ليُعثر عليه دائمًا عند تسجيل الدخول.'],
    ['Appearance', 'Apparence', 'المظهر'],
    ['Match the Mac, or always light or dark.', 'Comme le Mac, ou toujours clair ou sombre.', 'مثل جهازك، أو فاتح أو داكن دائمًا.'],
    ['Auto', 'Auto', 'تلقائي'],
    ['Light', 'Clair', 'فاتح'],
    ['Dark', 'Sombre', 'داكن'],
    ['Language', 'Langue', 'اللغة'],
    ['Auto follows your Mac\'s language.', 'Auto suit la langue de votre Mac.', '«تلقائي» يتبع لغة جهازك.'],
    ['Watch all apps, not just AI', 'Surveiller toutes les apps, pas seulement l’IA', 'مراقبة كل التطبيقات، لا الذكاء الاصطناعي فقط'],
    ['Also cover camera, screen, files and background jobs for every other app.', 'Couvre aussi la caméra, l’écran, les fichiers et les tâches en arrière-plan de toutes les autres apps.', 'يشمل أيضًا الكاميرا والشاشة والملفات والمهام في الخلفية لكل التطبيقات الأخرى.'],
    ['All set', 'C’est prêt', 'كل شيء جاهز'],
    ['You\'re protected', 'Vous êtes protégé', 'أنت محمي'],
    ['Here\'s what\'s switched on. You can change any of it later from', 'Voici ce qui est activé. Vous pourrez tout changer plus tard depuis', 'هذا ما تم تفعيله، ويمكنك تغيير أي شيء منه لاحقًا من'],
    ['at the bottom of the sidebar.', 'en bas de la barre latérale.', 'في أسفل الشريط الجانبي.'],
    ['Live popups for new access', 'Alertes en direct pour les nouveaux accès', 'تنبيهات فورية للصلاحيات الجديدة'],
    ['Included', 'Inclus', 'مشمولة'],
    ['Back', 'Retour', 'رجوع'],
    ['Not now', 'Plus tard', 'ليس الآن'],
    ['Set up', 'Configurer', 'إعداد'],
    ['Continue', 'Continuer', 'متابعة'],
    ['Start using it', 'Commencer', 'ابدأ الاستخدام'],
  ];

  // Texts that contain changing parts (numbers, names, dates). $1, $2… are the parts, left as they are.
  const W = s => tr(s); // translate one part if it's a known word
  const PATTERNS = [
    [/^(\d+) grants across (\d+) agents$/, ['$1 accès pour $2 agents', '$1 صلاحية لدى $2 وكلاء']],
    [/^Watching (\d+) grants across (\d+) agents\.$/, ['Surveillance de $1 accès pour $2 agents.', 'تجري مراقبة $1 صلاحية لدى $2 وكلاء.']],
    [/^Scanned (.+)$/, ['Analysé à $1', 'آخر فحص $1']],
    [/^Review (\d+) high-risk$/, ['Vérifier $1 à haut risque', 'مراجعة $1 عالية الخطورة']],
    [/^(All|High|Medium|Low) (\d+)$/, [m => `${W(m[1])} ${m[2]}`, m => `${W(m[1])} ${m[2]}`]],
    [/^(\d+) selected$/, ['$1 sélectionné(s)', 'تم تحديد $1']],
    [/^Revoke (\d+)$/, ['Retirer $1', 'سحب $1']],
    [/^Marked (\d+) as reviewed$/, ['$1 marqué(s) comme vérifié(s)', 'تم تعليم $1 كمُراجَع']],
    [/^Everything (.+) can access$/, ['Tout ce à quoi $1 peut accéder', 'كل ما يستطيع $1 الوصول إليه']],
    [/^Reviewed (.+)$/, ['Vérifié le $1', 'تمت المراجعة في $1']],
    [/^Will be revoked (.+) \(in (.+)\)$/, ['Sera retiré le $1 (dans $2)', 'سيُسحب في $1 (بعد $2)']],
    [/^(\d+) logs with secrets · (\d+) sharing data$/, ['$1 journaux avec des secrets · $2 partagent des données', 'سجلات بها مفاتيح سرية: $1 · تشارك البيانات: $2']],
    [/^Version (.+) is available$/, ['La version $1 est disponible', 'الإصدار \u2068$1\u2069 متاح']],
    [/^You have (.+)\. Download it and install it over this one\.$/, ['Vous avez la $1. Téléchargez-la et installez-la par-dessus celle-ci.', 'لديك الإصدار \u2068$1\u2069. نزّله وثبّته فوق هذا الإصدار.']],
    [/^This is version (.+)\.$/, ['Ceci est la version $1.', 'هذا هو الإصدار \u2068$1\u2069.']],
    [/^Couldn't export: (.+)$/, [`Impossible d’exporter${nb}: $1`, 'تعذّر التصدير: $1']],
    [/^Revoked automatically (.+)$/, ['Retiré automatiquement le $1', 'يُسحب تلقائيًا في $1']],
    [/^Step (\d) of (\d)$/, ['Étape $1 sur $2', 'الخطوة $1 من $2']],
    [/^✓ (.+)$/, [m => '✓ ' + W(m[1]), m => '✓ ' + W(m[1])]],
    [/^Appearance: (\w+) \(click to change\)$/, [m => `Apparence${nb}: ${W(m[1])} (cliquez pour changer)`, m => `المظهر: ${W(m[1])} (انقر للتغيير)`]],
    [/^Appearance: match the Mac$/, [`Apparence${nb}: comme le Mac`, 'المظهر: مثل جهازك']],
    [/^Appearance: (light|dark)$/, [m => `Apparence${nb}: ${W(m[1][0].toUpperCase() + m[1].slice(1)).toLowerCase()}`, m => `المظهر: ${W(m[1][0].toUpperCase() + m[1].slice(1))}`]],
    [/^Couldn't revoke: ([\s\S]+)$/, [`Impossible de retirer${nb}: $1`, 'تعذّر السحب: $1']],
    [/^Couldn't restore: ([\s\S]+)$/, [`Impossible de restaurer${nb}: $1`, 'تعذّرت الاستعادة: $1']],
    [/^Revoke "([\s\S]+)" from (.+)\?\n\n([\s\S]*)\n\nA backup is saved first, so you can undo this from History\.$/,
      [`Retirer «${nb}$1${nb}» à $2${nb}?\n\n$3\n\nUne sauvegarde est faite d’abord, vous pourrez annuler depuis l’Historique.`, 'سحب «$1» من $2؟\n\n$3\n\nتُحفظ نسخة احتياطية أولًا، فيمكنك التراجع من «السجل».']],
    [/^Revoke (\d+) grants?\?\n\n([\s\S]*)\n\nBackups are saved where possible, so you can undo from History\.$/,
      [`Retirer $1 accès${nb}?\n\n$2\n\nDes sauvegardes sont faites quand c’est possible, vous pourrez annuler depuis l’Historique.`, 'سحب $1 من الصلاحيات؟\n\n$2\n\nتُحفظ نسخ احتياطية حيثما أمكن، فيمكنك التراجع من «السجل».']],
    // "Claude Code · Tool permission · 3" and similar: translate each known part
    [/^(.+) · (\d+)$/, [m => `${W(m[1])} · ${m[2]}`, m => `${W(m[1])} · ${m[2]}`]],
  ];

  const COL = { fr: 1, ar: 2 };
  let lang = 'en', map = new Map();
  function tr(s) { return lang === 'en' ? s : (map.get(s) ?? s); }
  // The same app on Linux: say "computer" instead of "Mac", and "system tray" instead of "menu bar", in every language
  const OS = document.documentElement.dataset.os || new URLSearchParams(location.search).get('os') || 'mac';
  const OS_WORDS = OS === 'mac' ? null : {
    en: [[/\bthis Mac\b/g, 'this computer'], [/\byour Mac's\b/g, 'your computer\'s'], [/\byour Mac\b/g, 'your computer'], [/\b([Mm])atch the Mac\b/g, '$1atch the system'],
      [/\bthe menu bar\b/g, 'the system tray']],
    fr: [[/\bce Mac\b/g, 'cet ordinateur'], [/\bvotre Mac\b/g, 'votre ordinateur'], [/\b([Cc])omme le Mac\b/g, '$1omme le système'], [/la barre des menus/g, 'la zone de notification']],
    ar: [[/شريط القوائم/g, 'منطقة الإشعارات']],
  };
  function osWords(s) {
    if (!OS_WORDS || !s || !/Mac|menu|barre|شريط/.test(s)) return s;
    for (const [re, to] of OS_WORDS[lang]) s = s.replace(re, to);
    return s;
  }
  function translate(s) { return osWords(translateLang(s)); }
  function translateLang(s) {
    if (lang === 'en' || !s) return s;
    const lead = s.match(/^\s*/)[0], trail = s.match(/\s*$/)[0], core = s.trim();
    if (!core) return s;
    const hit = map.get(core);
    if (hit !== undefined) return lead + hit + trail;
    for (const [re, outs] of PATTERNS) {
      const m = core.match(re);
      if (!m) continue;
      const o = outs[COL[lang] - 1];
      return lead + (typeof o === 'function' ? o(m) : core.replace(re, o)) + trail;
    }
    if (core.includes(' · ')) { // "agent · type · detail": translate the parts we know
      const parts = core.split(' · '), out = parts.map(p => map.get(p) ?? p);
      if (out.some((p, i) => p !== parts[i])) return lead + out.join(' · ') + trail;
    }
    return s;
  }

  // never translate the user's own data
  const SKIP = '.ttl, .log, .insp h2, script, style, [data-raw]';
  const ATTRS = ['title', 'placeholder', 'aria-label'];
  // remember each text's English, so switching language (or back to English) always starts from the original
  const ORIG = new WeakMap(), ORIG_ATTR = new WeakMap();
  function walk(root) {
    if (root.nodeType === 3) { fixText(root); return; }
    if (root.nodeType !== 1 || root.closest(SKIP)) return;
    fixAttrs(root);
    const w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: n => n.nodeType === 1 && n.matches(SKIP) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
    });
    for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeType === 3 ? fixText(n) : fixAttrs(n);
  }
  function fixText(n) {
    if (n.parentElement && n.parentElement.closest(SKIP)) return;
    const rec = ORIG.get(n), base = rec && rec[1] === n.nodeValue ? rec[0] : n.nodeValue;
    const v = translate(base);
    if (v !== n.nodeValue) n.nodeValue = v;
    ORIG.set(n, [base, v]);
  }
  function fixAttrs(el) {
    let recs = ORIG_ATTR.get(el);
    for (const a of ATTRS) {
      const cur = el.getAttribute(a);
      if (!cur) continue;
      recs ||= {}; const rec = recs[a], base = rec && rec[1] === cur ? rec[0] : cur;
      const v = translate(base);
      if (v !== cur) el.setAttribute(a, v);
      recs[a] = [base, v];
    }
    if (recs) ORIG_ATTR.set(el, recs);
  }
  const obs = new MutationObserver(list => {
    for (const m of list) {
      if (m.type === 'characterData') fixText(m.target);
      else if (m.type === 'attributes') fixAttrs(m.target);
      else m.addedNodes.forEach(walk);
    }
  });

  function pick(pref) {
    if (pref === 'en' || pref === 'fr' || pref === 'ar') return pref;
    const sys = new URLSearchParams(location.search).get('syslang') || (navigator.languages && navigator.languages[0]) || navigator.language || 'en';
    const two = sys.slice(0, 2).toLowerCase();
    return COL[two] ? two : 'en';
  }
  window.setLang = pref => {
    const next = pick(pref);
    const changed = next !== lang;
    lang = next;
    map = new Map(lang === 'en' ? [] : T.map(r => [r[0], r[COL[lang]]]));
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    if (changed && document.body) walk(document.body);
    return changed; // the page re-renders to bring back English or apply the new language everywhere
  };
  window.t = translate;
  const browserConfirm = window.confirm.bind(window);
  // the Linux app shows its own dialog (with Confirm / Cancel in the app's language)
  window.confirm = msg => (window.nativeConfirm || browserConfirm)(translate(String(msg)));

  document.addEventListener('DOMContentLoaded', () => {
    obs.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  });
  setLang('auto');
})();
