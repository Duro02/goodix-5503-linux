// SPDX-License-Identifier: LGPL-2.1-or-later
#include <security/pam_appl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
conversation (int                        count,
              const struct pam_message **messages,
              struct pam_response      **responses,
              void                      *data)
{
  struct pam_response *reply;

  (void) data;
  if (count <= 0 || messages == NULL || responses == NULL)
    return PAM_CONV_ERR;

  reply = calloc ((size_t) count, sizeof *reply);
  if (reply == NULL)
    return PAM_BUF_ERR;

  for (int i = 0; i < count; i++)
    {
      if (messages[i] == NULL)
        {
          free (reply);
          return PAM_CONV_ERR;
        }
      if (messages[i]->msg_style == PAM_TEXT_INFO ||
          messages[i]->msg_style == PAM_ERROR_MSG)
        {
          if (messages[i]->msg != NULL)
            fprintf (stderr, "PAM: %s\n", messages[i]->msg);
          continue;
        }

      /* pam_fprintd never needs a textual response. Fail closed if a
       * different module unexpectedly asks for one. */
      free (reply);
      return PAM_CONV_ERR;
    }

  *responses = reply;
  return PAM_SUCCESS;
}

int
main (int argc, char **argv)
{
  const char *service = argc > 2 ? argv[2] : "goodix5503-ab-test";
  const char *user = argc > 1 ? argv[1] : getenv ("USER");
  struct pam_conv conv = { conversation, NULL };
  pam_handle_t *handle = NULL;
  int result;
  int end_result;

  if (user == NULL || *user == '\0')
    {
      fprintf (stderr, "usage: %s USER [PAM_SERVICE]\n", argv[0]);
      return 2;
    }

  result = pam_start (service, user, &conv, &handle);
  if (result == PAM_SUCCESS)
    result = pam_authenticate (handle, PAM_SILENT);

  if (handle != NULL)
    {
      end_result = pam_end (handle, result);
      if (end_result != PAM_SUCCESS)
        {
          fprintf (stderr, "pam_end failed: %d\n", end_result);
          return 2;
        }
    }

  if (result == PAM_SUCCESS)
    {
      puts ("pam-result=match");
      return 0;
    }
  if (result == PAM_AUTH_ERR || result == PAM_MAXTRIES)
    {
      puts ("pam-result=no-match");
      return 1;
    }

  fprintf (stderr, "PAM authentication error: %d\n", result);
  return 2;
}
