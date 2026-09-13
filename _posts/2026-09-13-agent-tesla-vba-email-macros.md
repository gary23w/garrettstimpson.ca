---
layout: post
title: "Agent Tesla Doesn't Need VBA to Be Unpatchable. It Needs One Exception"
date: 2026-09-13
categories: [malware, email, defense]
tags: [agent-tesla, vba, macros, malspam, phishing, microsoft-office, powershell, amsi, obfuscation, vba-stomping, mark-of-the-web, attack-surface-reduction]
excerpt: "An unpaid-invoice attachment, one permitted macro, and an obfuscated script chain were designed to install Agent Tesla in an APAC campaign. Obfuscation can beat literal signatures, but it does not make VBA invisible once reconstructed behavior reaches Office, AMSI, or the operating system."
---

An unpaid invoice arrives as a Word document or Excel spreadsheet. If the recipient opens it and active content is permitted, an image asks them to enable macros. Minimal VBA is designed to download a PowerShell script, write it to a temporary directory, and run it. The loader then delivers Agent Tesla, configured to communicate through Telegram and collect email contacts from the machine.

That is not a reconstructed hypothetical. It is the single infection chain HP documented in its [March 2026 Threat Insights Report](https://threatresearch.ext.hp.com/wp-content/uploads/2026/03/HP_Wolf_Security_Threat_Insights_Report_March_2026.pdf), based on threats observed in Q4 2025. HP saw both Word and Excel variants targeting the Asia-Pacific region. The lure was ordinary, the macros were minimal, and the final payload was a malware family old enough to have survived several generations of Office security guidance. HP Sure Click isolated and stopped the threats that reached its protected endpoints; the report does not claim those customers were compromised.

The tempting conclusion is that email macros are an unpatchable and undetectable hole in Office. That conclusion is wrong in two different ways.

VBA is a legitimate automation language, not a CVE. It can be disabled. The Office-for-Windows applications and versions covered by Microsoft's rollout now block internet-origin macros carrying Mark of the Web by default. Proofpoint later measured a sharp decline in macro-enabled email attachments as actors adapted to the announced controls. The residual problem is everything organizations build around that default: trusted locations, trusted publishers, old policy, missing provenance, and users whose real work still depends on active documents.

The macro is not the durable weakness. The trust handoff is. Obfuscation matters after that handoff because it can hide the words a static scanner expects to find, but it does not make the resulting behavior disappear.

One evidence boundary before going further: no Agent Tesla sample, malicious attachment, or source code was supplied for this post, and I did not execute one. This is a report-only assessment of HP's published analysis, scoped to that campaign. The harmless macro below was not run and is not a malware reproducer. It exists only to show where Office's trust decision sits and how a benign string can be reconstructed at runtime.

## The chain at a glance

The Word and Excel lures differed, but HP says both reached the same chain:

```text
UNPAID-INVOICE EMAIL
        |
        v
Word document or Excel spreadsheet
        |
        v
Social engineering asks the recipient to enable VBA
        |
        v
Minimal macro downloads a PowerShell script,
writes it to a temporary directory, and executes it
        |
        v
PowerShell decrypts and starts an intermediate loader
        |
        v
Loader places Agent Tesla in a legitimate .NET process
        |
        v
Telegram command-and-control
        |
        v
Local email-contact collection in the analyzed configuration
```

There is no CVSS score for this chain because there is no single software vulnerability to score. The attacker needs the message to arrive, the document to retain or acquire a path where active content is allowed, and the recipient or policy to permit the macro. HP's analysis established a chain capable of malware execution in the user's context. It did not report a privilege escalation or a successful compromise of a protected customer endpoint.

On the permitted-macro path HP analyzed, the VBA did not need to be clever. It was a delivery stub. HP says it retrieved a PowerShell stage, saved it under a temporary path, and launched it. The PowerShell code used RC4 to decrypt a preloaded array, replacing an XOR routine HP had seen in related loader chains. That operation produced another sequence of PowerShell code, which passed Agent Tesla through a known intermediate loader and into a legitimate .NET Framework process.

That distinction is important. HP called the VBA macros minimal. It did not say that the macros contained an RC4-encrypted Agent Tesla payload, and it did not attribute the RC4 routine to VBA. The encrypted array and RC4 implementation were in the PowerShell stage. I am not going to retrofit common macro-obfuscation techniques onto a sample whose source I have not inspected.

Every important boundary in that chain appears before the final malware family matters. The attachment crosses Office's macro trust decision. The document becomes code. Office becomes the parent of PowerShell. PowerShell becomes a loader. The loader makes a normal framework process carry the payload.

## What this sample did, and what it did not

Agent Tesla is not new. A [joint CISA and ACSC advisory](https://www.cisa.gov/sites/default/files/publications/aa22-216a-2021-top-malware-strains.pdf) listed it among the top malware strains of 2021, said malicious actors had used it for at least five years, and documented mass-phishing campaigns carrying it. The family can steal information from mail clients, browsers, and FTP applications and can capture screenshots.

Those are family capabilities. They are not all observations from this HP sample.

HP inspected the campaign's Agent Tesla configuration and found email-contact harvesting enabled while keylogging and screen capture were disabled. The malware was configured to scan a compromised machine for local contacts and send them through its command-and-control channel. Those addresses could become inputs to later phishing, but the report does not establish contact theft from a protected customer or that any collected contact received another message.

That narrower result matters. Saying “Agent Tesla can take screenshots” describes the product. Saying “this victim was screen-captured” would overstate the evidence. The same applies to credential theft, persistence, lateral movement, and administrator access: plausible family or operator activity is not observed campaign activity until the telemetry shows it.

The supported conclusion is still serious: the attachment was built for malware execution as the recipient, followed by a payload configured to extract a useful map of that person's email relationships. HP's isolation prevented the report from becoming a victim-impact account. A contact list is not just address data. It is a set of names, organizations, and trusted correspondents for writing the next unpaid invoice.

## Email is still the road. Spreadsheets are four percent

Email remains a leading malware route, but the denominator matters.

In HP's [June 2026 Threat Insights Report](https://threatresearch.ext.hp.com/wp-content/uploads/2026/06/HP_Wolf_Security_Threat_Insights_Report_June_2026.pdf), email delivered 57% of the endpoint malware threats caught by HP Sure Click in Q1 2026. At least 11% of those email threats had bypassed one or more gateway scanners. Those numbers come from opted-in HP customer telemetry and malware that reached protected endpoints. They are not measurements of all email, all endpoints, or the entire internet.

The file-type split is just as useful. Executables were 39% of threats in that corpus and archives were 38%. Malicious spreadsheets were 4%. Word-family documents accounted for another 7%, and the report does not say every one of those documents used VBA.

So two claims can be true at once: email is still the largest delivery vector in this current dataset, and malicious spreadsheets are a small minority of the files HP stopped. The Agent Tesla campaign is worth studying because a reduced technique remains viable wherever macros can run, not because macros dominate malware again.

The historical change is measurable. After Microsoft announced stronger default macro blocking, [Proofpoint observed macro-enabled attachments in its campaign data fall by roughly 66%](https://www.proofpoint.com/uk/blog/threat-insight/how-threat-actors-are-adapting-post-macro-world) between October 2021 and June 2022 and assessed that actors were adapting to the announced controls. Over the same period, actors increased their use of containers such as ISO and RAR files and Windows shortcuts.

Attackers moved because the control hurt them. That is what a successful mitigation looks like. It does not erase a technique from history; it changes the economics until another route becomes easier.

## VBA is not the unpatchable part

[Microsoft's current macro guidance](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked) describes the decision made by the Office-for-Windows applications and versions covered by its macro-blocking rollout when a macro-enabled file arrives from the internet.

Windows marks files from untrusted zones with Mark of the Web. Office checks whether the file came from a trusted location, whether its macro is signed by a trusted publisher, what policy says, and whether the document was already trusted. For the Office-for-Windows releases covered by the rollout, an ordinary internet-origin file carrying that mark reaches a hard block instead of the old one-click “Enable Content” path.

That is a real fix for the default email-attachment case. It is also a decision tree with exceptions:

- A file in a Trusted Location opens with macros enabled.
- A correctly signed macro can run when its publisher is trusted.
- Administrators can set policy to allow or block active content.
- A document trusted before the default changed can retain that trust.
- Some collaboration and synchronization paths do not attach Mark of the Web in the same way as a browser or mail download.

None of those behaviors is automatically a bypass. Businesses use signed macros and controlled locations because spreadsheets and documents still run payroll exports, inventory workflows, finance models, and internal reporting. The security problem appears when a broad exception stops representing the narrow workflow that justified it.

Mark of the Web is provenance, not a malware verdict. It says how Windows classified the file's origin. If the provenance is missing, removed through an approved workflow, or overridden by a trusted location, Office has less reason to treat the document as foreign. If a publisher certificate is trusted too broadly, the signature decision can authorize more code than the business process intended.

This is why “patch VBA” is the wrong remediation. No patch can perfectly classify the intent of arbitrary VBA while preserving every permitted automation. Policy can still refuse to execute it. The answer is to remove VBA where it is unnecessary and make every remaining exception small, signed, owned, and observable.

## What obfuscation actually hides

“The payload is obfuscated inside a VBA command” can describe three different things: a command argument assembled at the call site, an encoded blob carried and decoded by the macro, or a small macro launching a separately obfuscated stage. Those paths have different evidence. HP documented the third one here: minimal VBA launched PowerShell, and the RC4-protected array appeared in that PowerShell stage.

The practical strength of VBA obfuscation is much narrower than “undetectable.” It changes the representation a scanner or analyst sees before execution. A signature looking for one complete command, URL, filename, or object name can miss that value when the macro stores it as fragments and rebuilds it only in memory. The same idea can force a sandbox or analyst to spend more time reaching the meaningful branch.

These are recurring patterns in malicious VBA, not a universal ranking of what attackers use most often:

- **String fragmentation and character construction.** Instead of storing a suspicious value as one literal, the macro joins short fragments, reverses pieces, substitutes characters, or builds text from character codes. The parser sees the recipe. The complete string exists only after VBA evaluates it.

- **Encoded or encrypted data decoded at runtime.** A macro can carry a long blob as hexadecimal, Base64-like text, or numeric data and pass it through a decoder before use. Encoding changes representation; encryption additionally requires a key or derivation step. Neither tells us what the decoded data does until we inspect the result.

- **Data hidden outside the obvious module.** Fragments or blobs can live in worksheet cells, document variables, custom properties, form controls, labels, or VBA arrays. The visible procedure then looks small because it retrieves its real input from another stream or object in the Office file.

- **Junk, dead branches, comments, and random names.** Meaningless arithmetic, unused functions, copied legitimate-looking comments, and disposable identifiers increase the amount of code a scanner or analyst must normalize. This is camouflage, not a new execution primitive.

- **Invocation indirection.** A macro can create objects late, resolve a method only at runtime, or hand execution to COM, WMI, a Win32 API, or a legitimate Windows utility. This can remove an obvious literal from the source or change the process ancestry defenders expect. It does not remove the underlying file, process, API, memory, or network behavior.

- **VBA stomping.** This is a distinct and more advanced file-format trick. An Office VBA project can contain readable source streams and a separate compiled representation called p-code. [MITRE ATT&CK documents VBA stomping](https://attack.mitre.org/techniques/T1564/007/) as replacing the source with benign, empty, or random data while leaving malicious p-code to execute on a compatible Office version. A source-only extractor can therefore report something different from what Office runs. Version compatibility also constrains the technique, and source-versus-p-code discrepancies are themselves detection material.

A separate 2026 campaign shows how several of those ideas combine. [Unit 42's Boggy Serpens assessment](https://unit42.paloaltonetworks.com/boggy-serpens-threat-assessment/) describes VBA builders that stored hexadecimal payload data in a UserForm text-box property, decoded it with custom routines, wrote and renamed the result, and invoked it through APIs. Later variants used WMI or a Win32 process-creation call as indirection and added a very long CPU loop intended to outlast automated analysis. That is not evidence about HP's Agent Tesla macros. It is a current, independent example of the obfuscation categories above.

The limitation is unavoidable for the attacker: eventually, hidden data must become useful data. A downloader must produce a destination and request; a process launcher must produce a target and parameters; an API must receive actual arguments. [Microsoft's Office VBA and AMSI analysis](https://www.microsoft.com/en-us/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/) explains that Office instruments relevant VBA transitions into COM methods and Win32 APIs. At the dangerous call, those parameters have been resolved into plaintext, so Office can log the behavior and request a synchronous AMSI verdict.

That does not make every obfuscated macro detectable, and AMSI should never be treated as a perfect boundary. Coverage depends on supported Office and security-product integration, configuration, the behavior reached, and the quality of the verdict. Microsoft's documentation also describes policy scopes in which trusted documents, locations, publishers, or an enable-all setting can be excluded unless runtime scanning is configured more broadly. Obfuscation can still beat literal matching, mutate faster than signatures, complicate emulation, and delay human analysis. “Undetectable” is the part the evidence does not support.

## The PoC, honestly

This is the entire proof of concept:

```vb
Private Sub Workbook_Open()
    Dim firstPart As String
    Dim secondPart As String

    firstPart = "macro "
    secondPart = Chr$(114) & Chr$(97) & Chr$(110)
    ThisWorkbook.Worksheets(1).Range("A1").Value = firstPart & secondPart
End Sub
```

It is a harmless Excel event handler. If placed manually into a macro-enabled workbook and if Office decides that the macro is trusted and permitted, opening the workbook is expected to write `macro ran` into cell A1. The exact phrase does not appear as a contiguous literal in the VBA: the last word is reconstructed from character codes, then concatenated with the first fragment. A scanner limited to exact literal matching for `macro ran` would miss that phrase. A scanner can still flag the auto-open event or the reconstruction pattern, and Excel receives the resolved value when it performs the assignment.

I did not create the workbook or execute this macro. There is no observed output to report. It opens no shell, starts no process, writes no file, makes no network request, establishes no persistence, calls no operating-system API, and bypasses nothing. It proves nothing about Agent Tesla and cannot reproduce HP's campaign.

What it models is both the trust gate and one narrow static-analysis failure. `Workbook_Open` is dormant text until Office permits VBA execution. Before execution, a naive literal signature cannot see the complete phrase. At runtime, VBA must reconstruct it before Excel can use it. In a malicious macro, the same representational trick may hide a command or destination from literal matching, but the eventual COM, Win32, process, file, or network operation receives a resolved value. That runtime choke point is what Office instrumentation, AMSI, endpoint behavior monitoring, and process telemetry are designed to inspect.

The useful controls would be simple. With internet-origin macros blocked, the event should not run. With trusted-location, publisher, and per-application exceptions removed or tightly controlled, disabling all macros without notification should stop it regardless of the lure. In a deliberately managed trusted workflow, the marker may run, and that exception should be attributable to a specific location, publisher, policy, owner, and business purpose.

## The exception is the attack surface

The HP campaign was designed to persuade a person to enable VBA, but “the user clicked” is not a root cause. A user can only make that choice inside the policy and provenance environment the organization gives them.

If nobody in a role needs VBA, there should be no choice. After removing or tightly controlling Trusted Locations, trusted publishers, and per-application exceptions, Microsoft recommends **Disable all without notification** for those users. That turns the remaining macro path into a technical control instead of an awareness prompt.

Where macros are genuinely required, Microsoft's stronger recommendation is to allow only digitally signed macros and require a trusted publisher. The certificate must be deliberately deployed and governed. Trusted Locations should be rare, local where possible, and mapped to a named workflow rather than a department-wide dumping ground. A network share becoming “trusted” because blocking it generated support tickets is not a control; it is a second inbox with fewer warnings.

Then test the actual path. Send a known macro-enabled file through the same mail gateway, archive handling, browser, synchronization client, SharePoint flow, and file share employees use. Check whether Mark of the Web exists at every handoff and whether Office enforces the intended policy. A policy screenshot from an administration console does not prove that the file reaching a user's desktop carries the provenance that activates it.

The unpaid-invoice lure is designed to succeed in the space between configured policy and effective policy. That space is where exceptions accumulate.

## Detect reconstruction and the handoff, not the invoice

Invoice names, attachment hashes, sender domains, and Telegram infrastructure all change. The execution relationships are harder to replace.

For this campaign, the useful graph is:

```text
mail client -> Word or Excel -> PowerShell -> .NET process -> Telegram
```

Office spawning PowerShell is the sharpest edge in HP's chain. A macro writing script content under a temporary directory is another. A legitimate .NET Framework process receiving code from that chain deserves review even if the process itself is signed. Outbound Telegram traffic is not malicious by definition, but it becomes meaningful when it begins from a host immediately after that process tree.

[Microsoft's current Defender architecture](https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav) does not rely on one view of the file. It describes pre-execution file classification and heuristics, Office VBA and script visibility through AMSI, memory scanning, command-line scanning, emulation, and post-execution behavior monitoring across process sequences. Any one layer can miss. The point is that string mutation has to survive several different representations of the same action.

Microsoft's [Attack Surface Reduction rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) adds four useful controls here: block potentially obfuscated scripts; block Office applications from creating child processes; block Office from creating executable content; and block Win32 API calls from Office macros. Microsoft currently documents PowerShell support for the obfuscated-script rule, so that rule is relevant to a later stage such as HP's PowerShell loader rather than a direct scanner for VBA source. The child-process and executable-content rules map directly to HP's observed handoff. The Win32 rule constrains macros that call operating-system APIs even when they do not write a next stage to disk.

These controls can affect legitimate automation, so audit the real dependencies before enforcement. But do not stop at counting blocks. Record the parent Office process, document provenance, macro policy result, path written, child command line, network destination, and user identity on one timeline.

Static analysis still has a role. Normalize concatenated strings and character construction; decode inert blobs in an isolated analysis pipeline; inspect cells, custom properties, form controls, labels, and arrays; compare readable VBA source with compiled p-code; and score auto-open handlers alongside late-bound object creation and API declarations. Those are leads, not verdicts. Legitimate macro authors also split strings, protect intellectual property, and call approved automation interfaces.

Behavior analysis must cover the indirect path too. WMI or API-mediated process creation can make a simple `Excel -> child` alert incomplete, as the separate Boggy Serpens campaign demonstrates. Correlate the Office document and macro event with WMI provider activity, newly written content, subsequent script or executable launches, resolved command lines, memory behavior, and outbound connections. Obfuscation changes what is visible at each layer; correlation reconnects the layers.

The 11% of HP-observed email threats that passed at least one gateway scanner included many file types, not just Office documents. The number still demonstrates why endpoint controls remain necessary after mail filtering. For a macro document, the endpoint must decide whether the attachment becomes code.

## What to do about it

Start by separating people who need VBA from people who merely have it.

1. **Disable it completely where it has no business owner.** Remove or tightly control trust exceptions, then use the no-notification policy Microsoft recommends for users who do not need macros. A security prompt is an invitation; a block is a control.

2. **Make required macros signed-only.** Manage trusted publishers centrally, protect signing keys, inventory what each certificate signs, and revoke trust when ownership changes.

3. **Shrink Trusted Locations.** Give every location an owner, a specific workflow, and write permissions narrow enough that an email attachment cannot casually land there. Avoid trusted network locations unless there is no safer design.

4. **Verify provenance end to end.** Test whether email, archives, browsers, cloud synchronization, collaboration tools, and file shares preserve the origin information your Office policy expects.

5. **Scan the runtime, not only the file.** Confirm that supported Office builds and the endpoint security provider inspect VBA through AMSI, and configure runtime scan scope deliberately instead of assuming trusted documents are harmless. Evaluate the ASR rule for potentially obfuscated scripts for later script stages.

6. **Break the Office-to-process edge.** Evaluate ASR controls for Office child processes, executable content, injection, and macro Win32 calls. Move legitimate automations that need shells or downloads into managed services rather than granting every spreadsheet that capability.

7. **Hunt the reconstructed behavior as a chain.** Alert on suspicious Office-to-script or Office-to-executable transitions, including WMI-mediated creation, and on Office writing executable or script content to temporary paths. Preserve the original attachment, provenance metadata, VBA source and p-code, decoded analysis artefacts, process events, and network events.

8. **Investigate a successful run as potential credential exposure.** Isolate the endpoint, preserve process and network evidence, inspect the user's mail and browser secrets, and rotate credentials supported by the evidence. In this HP sample, also determine whether local email contacts were accessed and whether those correspondents received follow-on lures.

Do not solve this by banning every spreadsheet attachment at the gateway and declaring victory. HP's own numbers show attackers favor executables and archives, and Proofpoint's history shows they change containers when one route gets expensive. The durable control is preventing an untrusted business object from becoming an unobserved execution chain.

## The unpaid invoice

This Agent Tesla delivery pattern does not need a new vulnerability. It needs one believable reason for somebody to cross an existing trust boundary. The malware family's broader longevity also comes from continued development, reuse, and multiple delivery routes; VBA is only the route examined here.

Microsoft made that crossing much harder, and attackers measurably moved away from macros. Obfuscation keeps the residue useful because exact-string detection is brittle, not because VBA has become invisible. The Q4 2025 campaign is the residue: environments where VBA still has a business-shaped exception, provenance is weaker than policy assumes, runtime scanning is narrower than assumed, or Office can hand execution to a child process without being stopped.

The invoice is the story the attacker tells. The Office-to-process handoff is the part defenders can end.
