#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "file2pcap.h"
#include "smtp.h"
#include "helpers.h"
#include "quoted-printable.h"

#define SHORT_STRING_MAX 500
#define LONG_STRING_MAX 1000

char **load_random_words(const char *, int);
char *random_host(char **);
char *random_email(int, char **);

/************************************************************************************************************************/
int smtpRequest(struct handover *ho)
{
	char random_src_email[100];
	char random_dst_email[100];
	char random_host_string[100];

	time_t current_time = time(NULL);
	char current_time_string[100];
	strcpy(current_time_string, asctime(gmtime(&current_time)));

	srand(getpid() * time(NULL));
	char **random_words_list = load_random_words("/usr/share/dict/words", 100);
	strcpy(random_src_email, random_email(0, random_words_list));
	strcpy(random_dst_email, random_email(1, random_words_list));
	strcpy(random_host_string, random_host(random_words_list));

	char buffer[5000];
	char serverSmtpHeader[SHORT_STRING_MAX];
	char serverOptions1[SHORT_STRING_MAX];
	char clientMailFrom[SHORT_STRING_MAX];
	char serverSenderOk[SHORT_STRING_MAX];
	char clientReceiptTo[SHORT_STRING_MAX];
	char serverRecipientOk[SHORT_STRING_MAX];
	char clientMailBody[LONG_STRING_MAX];
	char serverClose[SHORT_STRING_MAX];
	char *badjoke = NULL;

	snprintf(serverSmtpHeader, SHORT_STRING_MAX, "220 %s ESMTP Sendmail 8.14.5/8.14.5; %s UTC\r\n", random_host_string, current_time_string); //FIXME - fix size
	char clientEhlo[] = "EHLO user\r\n";
	snprintf(serverOptions1, SHORT_STRING_MAX, "250-%s Hello user.%s [10.1.2.3], pleased to meet you\r\n", random_host_string, random_host_string); //FIXME - fix size
	char serverOptions2[] = "250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-EXPN\r\n250-VERB\r\n250-8BITMIME\r\n250-SIZE 32000000\r\n250-DSN\r\n250-ETRN\r\n250-STARTTLS\r\n250-DELIVERBY\r\n250 HELP\r\n";
	snprintf(clientMailFrom, SHORT_STRING_MAX, "MAIL FROM:<%s> SIZE=", random_src_email); //FIXME - fix size
	snprintf(serverSenderOk, SHORT_STRING_MAX, "250 2.1.0 <%s>... Sender ok\r\n", random_src_email);
	snprintf(clientReceiptTo, SHORT_STRING_MAX, "RCPT TO:<%s>\r\n", random_dst_email);
	snprintf(serverRecipientOk, SHORT_STRING_MAX, "250 2.1.5 <%s>... Recipient ok\r\n", random_dst_email);
	char clientData[] = "DATA\r\n";
	char serverEnterMail[] = "354 Enter mail, end with \".\" on a line by itself\r\n";
	snprintf(clientMailBody, LONG_STRING_MAX, "Message-ID: <537DC502.5080409@%s>\r\n"
								   "Date: %s UTC\r\n"
								   "From: <%s>\r\n"
								   "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Thunderbird/24.5.0\r\n"
								   "MIME-Version: 1.0\r\n"
								   "To: <%s>\r\n"
								   "Subject: file2pcap from InQuest\r\n"
								   "X-Enigmail-Version: 1.6\r\n"
								   "Content-Type: multipart/mixed;\r\n"
								   " boundary=\"------------020106020307040709020108\"\r\n\r\n"
								   "This is a multi-part message in MIME format.\r\n"
								   "--------------020106020307040709020108\r\n"
								   "Content-Type: text/plain; charset=ISO-8859-1\r\n"
								   "Content-Transfer-Encoding: 7bit\r\n\r\n",
			 random_host_string, current_time_string, random_src_email, random_dst_email);
	char clientAttachmentSeparator1[] = "--------------020106020307040709020108\r\n";
	char clientAttachment2b64[] = "\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"";
	char clientAttachment2qp[] = "\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Disposition: attachment; filename=\"";
	char clientAttachment2uu[] = "Content-Type: application/octet-stream\r\nEncoding: 446 uuencode\r\n\r\nbegin "; //Missing - FIXME Qj76bwlR5bGN.dOC 8DK9.QWQ
	char clientAttachmentSeparator2[] = "--------------020106020307040709020108--\r\n.\r\n";
	char serverMessageAccepted[] = "250 2.0.0 s4M9a2xl017623 Message accepted for delivery\r\n";
	char clientQuit[] = "QUIT\r\n";
	snprintf(serverClose, 500, "221 2.0.0 %s closing connection\r\n", random_host_string);

	tcpSendString(ho, serverSmtpHeader, FROM_SERVER);
	tcpSendString(ho, clientEhlo, TO_SERVER);
	tcpSendString(ho, serverOptions1, FROM_SERVER);
	tcpSendString(ho, serverOptions2, FROM_SERVER);
	snprintf(buffer, sizeof(buffer) - 1, "%s%d\r\n", clientMailFrom, 10000); //FIXME - fix size
	tcpSendString(ho, buffer, TO_SERVER);
	tcpSendString(ho, serverSenderOk, FROM_SERVER);
	tcpSendString(ho, clientReceiptTo, TO_SERVER);
	tcpSendString(ho, serverRecipientOk, FROM_SERVER);
	tcpSendString(ho, clientData, TO_SERVER);
	tcpSendString(ho, serverEnterMail, FROM_SERVER);

	tcpSendString(ho, clientMailBody, TO_SERVER);

	badjoke = badJoke();
	if (badjoke != NULL)
	{
		tcpSendString(ho, badjoke, TO_SERVER);
		free(badjoke);
	}

	tcpSendString(ho, clientAttachmentSeparator1, TO_SERVER);

	if ((ho->encoder == ENC_BASE64) || (ho->encoder == ENC_QUOTED_PRINTABLE))
	{
		snprintf(buffer, sizeof(buffer) - 1, "Content-Type: application/x-as400attachment;\r\n name=\"%s\"", ho->srcFile);
		tcpSendString(ho, buffer, TO_SERVER);
	}

	if (ho->encoder == ENC_BASE64)
		snprintf(buffer, sizeof(buffer) - 1, "%s%s\"\r\n\r\n", clientAttachment2b64, ho->srcFile);
	else if (ho->encoder == ENC_QUOTED_PRINTABLE)
		snprintf(buffer, sizeof(buffer) - 1, "%s%s\"\r\n\r\n", clientAttachment2qp, ho->srcFile);
	else if (ho->encoder == ENC_UU)
		snprintf(buffer, sizeof(buffer) - 1, "%s%s\r\n", clientAttachment2uu, ho->srcFile);
	else
		snprintf(buffer, sizeof(buffer) - 1, "%s%s\"\r\n\r\n", clientAttachment2b64, ho->srcFile);
	tcpSendString(ho, buffer, TO_SERVER);

	ho->direction = TO_SERVER;

	if (ho->encoder == ENC_BASE64)
		transferFileBase64(ho);
	else if (ho->encoder == ENC_QUOTED_PRINTABLE)
		transferFileQuotedPrintable(ho);
	else if (ho->encoder == ENC_UU)
		transferFileUU(ho);
	else
		transferFileBase64(ho);

	tcpSendString(ho, clientAttachmentSeparator2, TO_SERVER);
	tcpSendString(ho, serverMessageAccepted, FROM_SERVER);
	tcpSendString(ho, clientQuit, TO_SERVER);
	tcpSendString(ho, serverClose, FROM_SERVER);

	return (0);
}
