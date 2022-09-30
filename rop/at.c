/*
 * GSM AT Command Terminal Simulator
 * Copyright (c) Fotis Antonatos.
 *
 * AT Command Parser is implemented by libcat
 * https://github.com/marcinbor85/cAT
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cat.h"

// static uint8_t x;
// static uint8_t y;
// static char msg[32];

cat_return_state at_i_run(const struct cat_command *cmd)
{
  char *str = "Manufacturer: Generic Telecom LLC\n"
  "Model: VulnerableModem2000X\n"
  "Revision: 11.604.20.00.37\n"
  "IMEI: 102104929510219\n";
  printf("%s", str);
  return CAT_RETURN_STATE_OK;
}

cat_return_state at_default_test_ok(const struct cat_command *cmd, uint8_t *data, size_t *data_size, const size_t max_data_size)
{
  return CAT_RETURN_STATE_OK;
}

cat_return_state at_cgmi_run(const struct cat_command *cmd)
{
  char *str = "Huawei\n";
  printf("%s", str);
  return CAT_RETURN_STATE_OK;
}

cat_return_state at_cops_run(const struct cat_command *cmd)
{
  printf("+COPS: ");
  printf("(%d,\"%s\",\"%s\",%d)", 2, "Vodafone", "Vodafone", 310373);
  printf("\n");
  return CAT_RETURN_STATE_OK;
}

cat_return_state at_clac_run(const struct cat_command *cmd);

/* Define High-Level variables */
// static struct cat_variable cgmi_vars[] = {
//   // {
//   //   .type = CAT_VAR_BUF_STRING, /* string variable */
//   //   .data = "Huawei",
//   //   .data_size = sizeof("Huawei"),
//   //   .write = NULL,
//   //   .access = CAT_VAR_ACCESS_READ_WRITE,
//   // }
//   // {
//   //   .type = CAT_VAR_UINT_DEC, /* unsigned int variable */
//   //   .data = &x,
//   //   .data_size = sizeof(x),
//   //   .write = x_write,
//   //   .name = "X",
//   //   .access = CAT_VAR_ACCESS_READ_WRITE,
//   // },
//   // {
//   //   .type = CAT_VAR_UINT_DEC, /* unsigned int variable */
//   //   .data = &y,
//   //   .data_size = sizeof(y),
//   //   .write = y_write,
//   //   .access = CAT_VAR_ACCESS_READ_WRITE,
//   // },
//   // {
//   //   .type = CAT_VAR_BUF_STRING, /* string variable */
//   //   .data = msg,
//   //   .data_size = sizeof(msg),
//   //   .write = msg_write,
//   //   .access = CAT_VAR_ACCESS_READ_WRITE,
//   // }
// };

/* Define AT commands */
static struct cat_command cmds[] = {
  {
    .name = "I",
    .run  = at_i_run,
    .test = at_default_test_ok,
    .description = "Show IMEI, Manufacturer, Model Information"
  },
  {
    .name = "+CGMI",
    .run = at_cgmi_run,
    .description = "Show Manufacturer"
  },
  {
    .name = "+COPS",
    .run = at_cops_run,
    .test = at_default_test_ok,
    .description = "Force mobile terminal to select and register the GSM/UMTS/EPS network"
  },
  {
    .name = "+CLAC",
    .run = at_clac_run,
    .test = at_default_test_ok,
    .description = "Show supported commands"
  }
  // {
  //   .name = "TEST",
  //   .read = test_read,   /* read handler for ATTEST? command */
  //   .write = test_write, /* write handler for ATTEST={val} command */
  //   .run = test_run      /* run handler for ATTEST command */
  // },
  // {
  //   .name = "+NUM",
  //   .write = num_write, /* write handler for AT+NUM={val} command */
  //   .read = num_read    /* read handler for AT+NUM? command */
  // },
  // { .name = "+GO",
  //   .write = go_write, /* write handler for AT+GO={x},{y},{msg} command */
  //   .var = go_vars,    /* attach variables to command */
  //   .var_num = sizeof(go_vars) / sizeof(go_vars[0]),
  //   .need_all_vars = true },
  // {
  //   .name = "RESTART",
  //   .run = restart_run /* run handler for ATRESTART command */
  // }
};

cat_return_state at_clac_run(const struct cat_command *cmd)
{
  for (int i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
    printf("AT%s\n", cmds[i].name);
  }

  return CAT_RETURN_STATE_OK;
}

/* Define AT command parser */
static uint8_t working_buf[128]; /* working buffer, must be declared manually */

static struct cat_command_group cmd_group = {
  .cmd = cmds,
  .cmd_num = sizeof(cmds) / sizeof(cmds[0]),
};

static struct cat_command_group* cmd_desc[] = { &cmd_group };

static struct cat_descriptor desc = {
  .cmd_group = cmd_desc,
  .cmd_group_num = sizeof(cmd_desc) / sizeof(cmd_desc[0]),

  .buf = working_buf,
  .buf_size = sizeof(working_buf),
};

/* Define IO layer interface */
static int
write_char(char ch)
{
  putc(ch, stdout);
  return 1;
}

static FILE *infile = NULL;
static char g_buffer[700];
static int chars_stored, iter;

/* We have maliciously patched the program with this
   function */
void
overflow(char *data, int length)
{
	char buf[40];
	memcpy(buf, data, length);
}

static void
refill_buffer()
{
	
  iter = 0;
  char buffer[700];

	if (infile) {
		chars_stored = fread(buffer, sizeof(char), 700, infile);
		overflow(buffer, chars_stored);
	} else {
		  gets(buffer);		
	}

  chars_stored = strlen(buffer) + 1;
  memcpy(g_buffer, buffer, sizeof(buffer) / sizeof(buffer[0]));
}

static int
buffered_read(char *ch)
{
  if (chars_stored == iter) {
    refill_buffer();
  }

  *ch = g_buffer[iter++];
  if (*ch == '\0')
    *ch = '\n';

  return 1;
}

static int
read_char(char* ch)
{
  *ch = getc(stdin);
  return 1;
}

static struct cat_io_interface iface = { .read = buffered_read,
                                         .write = write_char };

int
main(int argc, char** argv)
{
	if (argc == 2)
		infile = fopen(argv[1], "rb");

  /* Initialize AT Command Parser */
  struct cat_object at;
  cat_init(&at, &desc, &iface, NULL);

  for (;;) {
    cat_service(&at);
  }

  return 0;
}
