// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/email"
)

func TestEmailReport(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	crash.Maintainers = []string{`"Foo Bar" <foo@bar.com>`, `bar@foo.com`, `idont@want.EMAILS`}
	c.client2.ReportCrash(crash)

	// Report the crash over email and check all fields.
	var sender0, extBugID0, body0 string
	var dbBug0 *Bug
	{
		msg := c.pollEmailBug()
		sender0 = msg.Sender
		body0 = msg.Body
		sender, extBugID, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		extBugID0 = extBugID
		dbBug, dbCrash, dbBuild := c.loadBug(extBugID0)
		dbBug0 = dbBug
		crashLogLink := externalLink(c.ctx, textCrashLog, dbCrash.Log)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		c.expectEQ(sender, fromAddr(c.ctx))
		to := config.Namespaces["test2"].Reporting[0].Config.(*EmailConfig).Email
		c.expectEQ(msg.To, []string{to})
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot found the following crash on:

HEAD commit:    11111111 kernel_commit_title1
git tree:       repo1 branch1
console output: %[2]v
kernel config:  %[3]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler1
CC:             [bar@foo.com foo@bar.com idont@want.EMAILS]

Unfortunately, I don't have any reproducer for this crash yet.

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1

---
This bug is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this bug report. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.`,
			extBugID0, crashLogLink, kernelConfigLink))
		c.checkURLContents(crashLogLink, crash.Log)
		c.checkURLContents(kernelConfigLink, build.KernelConfig)
	}

	// Emulate receive of the report from a mailing list.
	// This should update the bug with the link/Message-ID.
	// nolint: lll
	incoming1 := fmt.Sprintf(`Sender: syzkaller@googlegroups.com
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <1234>
Subject: crash1
From: %v
To: foo@bar.com
Content-Type: text/plain

Hello

syzbot will keep track of this bug report.
If you forgot to add the Reported-by tag, once the fix for this bug is merged
into any tree, please reply to this email with:
#syz fix: exact-commit-title
To mark this as a duplicate of another syzbot report, please reply with:
#syz dup: exact-subject-of-another-report
If it's a one-off invalid bug report, please reply with:
#syz invalid

-- 
You received this message because you are subscribed to the Google Groups "syzkaller" group.
To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
To post to this group, send email to syzkaller@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/1234@google.com.
For more options, visit https://groups.google.com/d/optout.
`, sender0)

	c.expectOK(c.POST("/_ah/mail/", incoming1))

	// Emulate that somebody sends us our own email back without quoting.
	// We used to extract "#syz fix: exact-commit-title" from it.
	c.incomingEmail(sender0, body0)

	c.incomingEmail(sender0, "I don't want emails", EmailOptFrom(`"idont" <idont@WANT.emails>`))
	c.expectNoEmail()

	// This person sends an email and is listed as a maintainer, but opt-out of emails.
	// We should not send anything else to them for this bug. Also don't warn about no mailing list in CC.
	c.incomingEmail(sender0, "#syz uncc", EmailOptFrom(`"IDONT" <Idont@want.emails>`), EmailOptCC(nil))
	c.expectNoEmail()

	// Now report syz reproducer and check updated email.
	build2 := testBuild(10)
	build2.Arch = "386"
	build2.KernelRepo = testConfig.Namespaces["test2"].Repos[0].URL
	build2.KernelBranch = testConfig.Namespaces["test2"].Repos[0].Branch
	build2.KernelCommitTitle = "a really long title, longer than 80 chars, really long-long-long-long-long-long title"
	c.client2.UploadBuild(build2)
	crash.BuildID = build2.ID
	crash.ReproOpts = []byte("repro opts")
	crash.ReproSyz = []byte("getpid()")
	syzRepro := []byte(fmt.Sprintf("# https://testapp.appspot.com/bug?id=%v\n%s#%s\n%s",
		dbBug0.keyHash(), syzReproPrefix, crash.ReproOpts, crash.ReproSyz))
	c.client2.ReportCrash(crash)

	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.Sender, sender0)
		sender, _, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		_, dbCrash, dbBuild := c.loadBug(extBugID0)
		reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
		crashLogLink := externalLink(c.ctx, textCrashLog, dbCrash.Log)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		c.expectEQ(sender, fromAddr(c.ctx))
		to := []string{
			"bugs2@syzkaller.com",
			"bugs@syzkaller.com", // This is from incomingEmail.
			"default@sender.com", // This is from incomingEmail.
			"foo@bar.com",
			config.Namespaces["test2"].Reporting[0].Config.(*EmailConfig).Email,
		}
		c.expectEQ(msg.To, to)
		c.expectEQ(msg.Subject, "Re: "+crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Headers["In-Reply-To"], []string{"<1234>"})
		c.expectEQ(msg.Body, fmt.Sprintf(`syzbot has found a reproducer for the following crash on:

HEAD commit:    10101010 a really long title, longer than 80 chars, really..
git tree:       repo10alias
console output: %[3]v
kernel config:  %[4]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler10
userspace arch: i386
syz repro:      %[2]v
CC:             [bar@foo.com foo@bar.com maintainers@repo10.org bugs@repo10.org]

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1
`, extBugID0, reproSyzLink, crashLogLink, kernelConfigLink))
		c.checkURLContents(reproSyzLink, syzRepro)
		c.checkURLContents(crashLogLink, crash.Log)
		c.checkURLContents(kernelConfigLink, build2.KernelConfig)
	}

	// Now upstream the bug and check that it reaches the next reporting.
	c.incomingEmail(sender0, "#syz upstream")

	sender1, extBugID1 := "", ""
	{
		msg := c.pollEmailBug()
		sender1 = msg.Sender
		c.expectNE(sender1, sender0)
		sender, extBugID, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		extBugID1 = extBugID
		_, dbCrash, dbBuild := c.loadBug(extBugID1)
		reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
		crashLogLink := externalLink(c.ctx, textCrashLog, dbCrash.Log)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		c.expectEQ(sender, fromAddr(c.ctx))
		c.expectEQ(msg.To, []string{
			"bar@foo.com", "bugs@repo10.org", "bugs@syzkaller.com",
			"default@maintainers.com", "foo@bar.com", "maintainers@repo10.org"})
		c.expectEQ(msg.Subject, crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`Hello,

syzbot found the following crash on:

HEAD commit:    10101010 a really long title, longer than 80 chars, really..
git tree:       repo10alias
console output: %[3]v
kernel config:  %[4]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler10
userspace arch: i386
syz repro:      %[2]v
CC:             [bar@foo.com foo@bar.com maintainers@repo10.org bugs@repo10.org]

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1

---
This bug is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this bug report. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
syzbot can test patches for this bug, for details see:
https://goo.gl/tpsmEJ#testing-patches`,
			extBugID1, reproSyzLink, crashLogLink, kernelConfigLink))
		c.checkURLContents(reproSyzLink, syzRepro)
		c.checkURLContents(crashLogLink, crash.Log)
		c.checkURLContents(kernelConfigLink, build2.KernelConfig)
	}

	// Model that somebody adds more emails to CC list.
	incoming3 := fmt.Sprintf(`Sender: syzkaller@googlegroups.com
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <1234>
Subject: crash1
From: foo@bar.com
To: %v
CC: new@new.com, "another" <another@another.com>, bar@foo.com, bugs@syzkaller.com, foo@bar.com
Content-Type: text/plain

+more people
`, sender1)

	c.expectOK(c.POST("/_ah/mail/", incoming3))

	// Now upload a C reproducer.
	crash.ReproC = []byte("int main() {}")
	crash.Maintainers = []string{"\"qux\" <qux@qux.com>"}
	c.client2.ReportCrash(crash)
	cRepro := []byte(fmt.Sprintf("// https://testapp.appspot.com/bug?id=%v\n%s",
		dbBug0.keyHash(), crash.ReproC))

	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.Sender, sender1)
		sender, _, err := email.RemoveAddrContext(msg.Sender)
		c.expectOK(err)
		_, dbCrash, dbBuild := c.loadBug(extBugID1)
		reproCLink := externalLink(c.ctx, textReproC, dbCrash.ReproC)
		reproSyzLink := externalLink(c.ctx, textReproSyz, dbCrash.ReproSyz)
		crashLogLink := externalLink(c.ctx, textCrashLog, dbCrash.Log)
		kernelConfigLink := externalLink(c.ctx, textKernelConfig, dbBuild.KernelConfig)
		c.expectEQ(sender, fromAddr(c.ctx))
		c.expectEQ(msg.To, []string{
			"another@another.com", "bar@foo.com", "bugs@repo10.org",
			"bugs@syzkaller.com", "default@maintainers.com", "foo@bar.com",
			"maintainers@repo10.org", "new@new.com", "qux@qux.com"})
		c.expectEQ(msg.Subject, "Re: "+crash.Title)
		c.expectEQ(len(msg.Attachments), 0)
		c.expectEQ(msg.Body, fmt.Sprintf(`syzbot has found a reproducer for the following crash on:

HEAD commit:    10101010 a really long title, longer than 80 chars, really..
git tree:       repo10alias
console output: %[4]v
kernel config:  %[5]v
dashboard link: https://testapp.appspot.com/bug?extid=%[1]v
compiler:       compiler10
userspace arch: i386
syz repro:      %[3]v
C reproducer:   %[2]v
CC:             [qux@qux.com maintainers@repo10.org bugs@repo10.org]

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+%[1]v@testapp.appspotmail.com

report1
`, extBugID1, reproCLink, reproSyzLink, crashLogLink, kernelConfigLink))
		c.checkURLContents(reproCLink, cRepro)
		c.checkURLContents(reproSyzLink, syzRepro)
		c.checkURLContents(crashLogLink, crash.Log)
		c.checkURLContents(kernelConfigLink, build2.KernelConfig)
	}

	// Send an invalid command.
	incoming4 := fmt.Sprintf(`Sender: syzkaller@googlegroups.com
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <abcdef>
Subject: title1
From: foo@bar.com
To: %v
Content-Type: text/plain

#syz bad-command
`, sender1)

	c.expectOK(c.POST("/_ah/mail/", incoming4))

	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.To, []string{"<foo@bar.com>"})
		c.expectEQ(msg.Subject, "Re: title1")
		c.expectEQ(msg.Headers["In-Reply-To"], []string{"<abcdef>"})
		if !strings.Contains(msg.Body, `> #syz bad-command

unknown command "bad-command"
`) {
			t.Fatal("no unknown command reply for bad command")
		}
	}

	// Now mark the bug as fixed.
	c.incomingEmail(sender1, "#syz fix: some: commit title", EmailOptCC(nil))
	reply := c.pollEmailBug().Body
	// nolint: lll
	c.expectEQ(reply, `> #syz fix: some: commit title

Your 'fix:' command is accepted, but please keep bugs@syzkaller.com mailing list in CC next time. It serves as a history of what happened with each bug report. Thank you.

`)

	// Check that the commit is now passed to builders.
	builderPollResp, _ := c.client2.BuilderPoll(build.Manager)
	c.expectEQ(len(builderPollResp.PendingCommits), 1)
	c.expectEQ(builderPollResp.PendingCommits[0], "some: commit title")

	build3 := testBuild(3)
	build3.Manager = build.Manager
	build3.Commits = []string{"some: commit title"}
	c.client2.UploadBuild(build3)

	build4 := testBuild(4)
	build4.Manager = build2.Manager
	build4.Commits = []string{"some: commit title"}
	c.client2.UploadBuild(build4)

	// New crash must produce new bug in the first reporting.
	c.client2.ReportCrash(crash)
	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.Subject, crash.Title+" (2)")
		c.expectNE(msg.Sender, sender0)
	}
}

// Bug must not be mailed to maintainers if maintainers list is empty.
func TestEmailNoMaintainers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash := testCrash(build, 1)
	c.client2.ReportCrash(crash)

	sender := c.pollEmailBug().Sender

	incoming1 := fmt.Sprintf(`Sender: syzkaller@googlegroups.com
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <1234>
Subject: crash1
From: %v
To: foo@bar.com
Content-Type: text/plain

#syz upstream
`, sender)
	c.expectOK(c.POST("/_ah/mail/", incoming1))
}

// Basic dup scenario: mark one bug as dup of another.
func TestEmailDup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "BUG: slightly more elaborate title"
	c.client2.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash1.Title = "KASAN: another title"
	c.client2.ReportCrash(crash2)

	c.expectOK(c.GET("/email_poll"))
	msg1 := c.pollEmailBug()
	msg2 := c.pollEmailBug()

	// Dup crash2 to crash1.
	c.incomingEmail(msg2.Sender, "#syz dup: BUG: slightly more elaborate title")
	c.expectNoEmail()

	// Second crash happens again
	crash2.ReproC = []byte("int main() {}")
	c.client2.ReportCrash(crash2)
	c.expectNoEmail()

	// Now close the original bug, and check that new bugs for dup are now created.
	c.incomingEmail(msg1.Sender, "#syz invalid")

	// uncc command must not trugger error reply even for closed bug.
	c.incomingEmail(msg1.Sender, "#syz uncc", EmailOptCC(nil))
	c.expectNoEmail()

	// New crash must produce new bug in the first reporting.
	c.client2.ReportCrash(crash2)
	{
		msg := c.pollEmailBug()
		c.expectEQ(msg.Subject, crash2.Title+" (2)")
	}
}

func TestEmailUndup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	crash1 := testCrash(build, 1)
	crash1.Title = "BUG: slightly more elaborate title"
	c.client2.ReportCrash(crash1)

	crash2 := testCrash(build, 2)
	crash1.Title = "KASAN: another title"
	c.client2.ReportCrash(crash2)

	c.expectOK(c.GET("/email_poll"))
	msg1 := c.pollEmailBug()
	msg2 := c.pollEmailBug()

	// Dup crash2 to crash1.
	c.incomingEmail(msg2.Sender, "#syz dup BUG: slightly more elaborate title")
	c.expectNoEmail()

	// Undup crash2.
	c.incomingEmail(msg2.Sender, "#syz undup")
	c.expectNoEmail()

	// Now close the original bug, and check that new crashes for the dup does not create bugs.
	c.incomingEmail(msg1.Sender, "#syz invalid")
	c.client2.ReportCrash(crash2)
	c.expectNoEmail()
}

func TestEmailCrossReportingDup(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.client2.UploadBuild(build)

	tests := []struct {
		bug    int
		dup    int
		result bool
	}{
		{0, 0, true},
		{0, 1, false},
		{0, 2, false},
		{1, 0, false},
		{1, 1, true},
		{1, 2, true},
		{2, 0, false},
		{2, 1, false},
		{2, 2, true},
	}
	for i, test := range tests {
		t.Logf("duping %v->%v, expect %v", test.bug, test.dup, test.result)
		c.advanceTime(24 * time.Hour) // to not hit email limit per day
		crash1 := testCrash(build, 1)
		crash1.Title = fmt.Sprintf("bug_%v", i)
		c.client2.ReportCrash(crash1)
		bugSender := c.pollEmailBug().Sender
		for j := 0; j < test.bug; j++ {
			c.incomingEmail(bugSender, "#syz upstream")
			bugSender = c.pollEmailBug().Sender
		}

		crash2 := testCrash(build, 2)
		crash2.Title = fmt.Sprintf("dup_%v", i)
		c.client2.ReportCrash(crash2)
		dupSender := c.pollEmailBug().Sender
		for j := 0; j < test.dup; j++ {
			c.incomingEmail(dupSender, "#syz upstream")
			dupSender = c.pollEmailBug().Sender
		}

		c.incomingEmail(bugSender, "#syz dup: "+crash2.Title)
		if test.result {
			c.expectNoEmail()
		} else {
			msg := c.pollEmailBug()
			if !strings.Contains(msg.Body, "> #syz dup:") ||
				!strings.Contains(msg.Body, "Can't dup bug to a bug in different reporting") {
				c.t.Fatalf("bad reply body:\n%v", msg.Body)
			}
		}
	}
}

func TestEmailErrors(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// No reply for email without bug hash and no commands.
	c.incomingEmail("syzbot@testapp.appspotmail.com", "Investment Proposal")
	c.expectNoEmail()

	// If email contains a command we need to reply.
	c.incomingEmail("syzbot@testapp.appspotmail.com", "#syz invalid")
	reply := c.pollEmailBug()
	c.expectEQ(reply.To, []string{"<default@sender.com>"})
	c.expectEQ(reply.Body, `> #syz invalid

I see the command but can't find the corresponding bug.
Please resend the email to syzbot+HASH@testapp.appspotmail.com address
that is the sender of the bug report (also present in the Reported-by tag).

`)

	c.incomingEmail("syzbot+123@testapp.appspotmail.com", "#syz invalid")
	reply = c.pollEmailBug()
	c.expectEQ(reply.Body, `> #syz invalid

I see the command but can't find the corresponding bug.
The email is sent to  syzbot+HASH@testapp.appspotmail.com address
but the HASH does not correspond to any known bug.
Please double check the address.

`)
}
