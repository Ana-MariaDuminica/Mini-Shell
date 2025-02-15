// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define ERR			2

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	// We get the path for the cd command
	char *path = get_word(dir);
	int value = -1;

	if (path != NULL) {
		value = chdir(path);

	} else {
		char *homeEnv = getenv("HOME");

		if (homeEnv != NULL)
			value = chdir(homeEnv);
	}

	free(path);
	return value;
}

static bool cd_command(simple_command_t *s)
{
	int fdOut = -1;
	int fdErr = -1;
	int fdOutErr = -1;

	char *stdout_file = get_word(s->out);
	char *stderr_file = get_word(s->err);

	int flags = O_WRONLY | O_CREAT;

	if (s->io_flags == 0x01)
		flags |= O_APPEND;
	else if (s->io_flags == 0x00)
		flags |= O_TRUNC;
	else if (s->io_flags == 0x02)
		flags |= O_APPEND;


	if (stdout_file != NULL && stderr_file != NULL && strcmp(stderr_file, stdout_file) == 0) {
		fdOutErr = open(stdout_file, flags, 0644);
		if (fdOutErr < 0) {
			perror("open");
			close(fdOutErr);
			free(stdout_file);
			free(stderr_file);
			exit(EXIT_FAILURE);
		}

	} else {
		if (stdout_file != NULL) {
			fdOut = open(stdout_file, flags, 0644);
			if (fdOut < 0) {
				perror("open");
				close(fdOut);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}
		}

		if (stderr_file != NULL) {
			fdErr = open(stderr_file, flags, 0644);
			if (fdErr < 0) {
				perror("open");
				close(fdErr);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}
		}
	}

	int val = shell_cd(s->params);

	if (val == -1 && fdErr != -1) {
		FILE *errFile = fdopen(fdErr, "w");

		fprintf(errFile, "%s\n", "Error at changing directory");
		fclose(errFile);
	} else if (val == -1 && fdErr == -1) {
		fprintf(stderr, "%s\n", "Error at changing directory");
	}
	free(stdout_file);
	free(stderr_file);

	close(fdOut);
	close(fdErr);
	close(fdOutErr);

	return val;
}


static bool pwd_command(simple_command_t *s)
{
	int fdOut = -1;
	int fdErr = -1;

	char *stdout_file = get_word(s->out);
	char *stderr_file = get_word(s->err);

	char cwd[1024];

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		perror("getcwd() error");
		return false; // false in case of error
	}

	if (stdout_file != NULL) {
		fdOut = open(stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fdOut < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}

		dprintf(fdOut, "%s\n", cwd);
	}

	if (stderr_file != NULL) {
		fdErr = open(stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fdErr < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
	}

	free(stdout_file);
	free(stderr_file);

	if (fdOut != -1)
		close(fdOut);

	if (fdErr != -1)
		close(fdErr);

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	//return 0; /* TODO: Replace with actual exit code. */
	exit(0);
}

void redirect(simple_command_t *s, int *fdIn, int *fdOut, int *fdErr, int *fdOutErr)
{
	int flags = O_WRONLY | O_CREAT;

	if (s->io_flags == 0x01)
		flags |= O_APPEND;
	if (s->io_flags == 0x00)
		flags |= O_TRUNC;
	if (s->io_flags == 0x02)
		flags |= O_APPEND;


	char *stdin_file = get_word(s->in);
	char *stdout_file = get_word(s->out);
	char *stderr_file = get_word(s->err);


	if (stdin_file != NULL) {
		*fdIn = open(stdin_file, O_RDONLY);
		if ((*fdIn) < 0) {
			perror("open");
			close(*fdIn);
			free(stdin_file);
			free(stdout_file);
			free(stderr_file);
			exit(EXIT_FAILURE); // Handle open error
		}

		if (dup2((*fdIn), READ) == -1) {
			perror("dup2");
			close(*fdIn);
			free(stdin_file);
			free(stdout_file);
			free(stderr_file);
			exit(EXIT_FAILURE); // Handle dup2 error
		}
	}

	if (stdout_file != NULL && stderr_file != NULL && strcmp(stderr_file, stdout_file) == 0) {
		*fdOutErr = open(stdout_file, flags, 0644);
		if ((*fdOutErr) < 0) {
			perror("open");
			close((*fdOutErr));
			free(stdin_file);
			free(stdout_file);
			free(stderr_file);
			exit(EXIT_FAILURE);
		}

		if (dup2((*fdOutErr), WRITE) == -1 || dup2((*fdOutErr), ERR) == -1) {
			perror("dup2");
			close((*fdOutErr));
			free(stdin_file);
			free(stdout_file);
			free(stderr_file);
			exit(EXIT_FAILURE);
		}

	} else {
		if (stdout_file != NULL) {
			*fdOut = open(stdout_file, flags, 0644);
			if ((*fdOut) < 0) {
				perror("open");
				close((*fdOut));
				free(stdin_file);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}

			if (dup2((*fdOut), WRITE) == -1) {
				perror("dup2");
				close((*fdOut));
				free(stdin_file);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}
		}

		if (stderr_file != NULL) {
			*fdErr = open(stderr_file, flags, 0644);
			if ((*fdErr) < 0) {
				perror("open");
				free(stdin_file);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}

			if (dup2((*fdErr), ERR) == -1) {
				perror("dup2");
				close((*fdErr));
				free(stdin_file);
				free(stdout_file);
				free(stderr_file);
				exit(EXIT_FAILURE);
			}
		}
	}
	free(stdin_file);
	free(stdout_file);
	free(stderr_file);
}


/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL)
		return SHELL_EXIT;

	if (level < 0)
		return SHELL_EXIT;

	char *command = get_word(s->verb);
	/* TODO: If builtin command, execute the command. */
	if (strcmp(command, "cd") == 0) {
		free(command);
		return cd_command(s);
	}
	if (strcmp(command, "exit") == 0) {
		free(command);
		return shell_exit();
	}
	if (strcmp(command, "pwd") == 0) {
		free(command);
		return pwd_command(s);
	}
	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (strchr(command, '=') != 0) {
		free(command);
	//	char *saveptr;
		char *name = __strtok_r(NULL, "=", &command);
		char *value = __strtok_r(NULL, "=", &command);

		if (value != NULL && name != NULL) {
			setenv(name, value, 1);
			return 0;
		}

		fprintf(stderr, "Error: Invalid variable assignment\n");
		return 1;
	}
	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */


	int numArg = 0;
	int status;

	char **argv = get_argv(s, &numArg);

	pid_t pid = fork();

	if (pid < 0)
		abort();


	if (pid > 0) {
		waitpid(pid, &status, 0);
		for (int i = 0; i < numArg; i++)
			free(argv[i]);
		free(argv);
		free(command);

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return 1;
	}

	int value = 0;

	int fdIn = -1, fdOut = -1, fdErr = -1, fdOutErr = -1;

	redirect(s, &fdIn, &fdOut, &fdErr, &fdOutErr);

	value = execvp(command, argv);

	close(fdIn);
	close(fdOut);
	close(fdErr);
	close(fdOutErr);

	if (value == -1) {
		fprintf(stderr, "%s '%s'\n", "Execution failed for", command);
		abort();
	}

	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

//	return true; /* TODO: Replace with actual exit status. */
	int status1, status2;

	pid_t pid1 = fork();

	if (pid1 < 0) {
		perror("Fork failed");
		return false;
	} else if (pid1 == 0) {
		// Child process 1 executes cmd1
		int retValue = parse_command(cmd1, level, father);

		exit(retValue);
	}

	pid_t pid2 = fork();

	if (pid2 == 0) {
		// Child process 2 executes cmd2
		int retValue = parse_command(cmd2, level, father);

		exit(retValue);
	} else if (pid2 < 0) {
		perror("Fork failed");
		return false;
	}

	// Parent process waits for both children to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// Return true if both commands were successful (exit status 0)
	return (WIFEXITED(status1) && WIFEXITED(status2) && WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefd[2]; // Pipe file descriptors
	pid_t pid1, pid2;
	int status1, status2;

	// Creating the pipe
	if (pipe(pipefd) == -1) {
		perror("Pipe failed");
		abort();
	}

	pid1 = fork();
	if (pid1 < 0) {
		perror("Fork failed");
		abort();
	}

	if (pid1 == 0) { // Child process 1 (executes cmd1)
		close(pipefd[0]); // Close the read end of the pipe

		// Redirect standard output to the write end of the pipe
		if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
			perror("Dup2 failed");
			exit(EXIT_FAILURE);
		}

		int retValue = parse_command(cmd1, level, father);

		close(pipefd[1]);
		exit(retValue);
	}

	pid2 = fork();
	if (pid2 < 0) {
		perror("Fork failed");
		return false;
	}

	if (pid2 == 0) { // Child process 2 (executes cmd2)
		close(pipefd[1]); // Close the write end of the pipe

		// Redirect standard input to the read end of the pipe
		if (dup2(pipefd[0], STDIN_FILENO) == -1) {
			perror("Dup2 failed");
			exit(EXIT_FAILURE);
		}

		int retValue = parse_command(cmd2, level, father);

		close(pipefd[0]);
		exit(retValue);
	}

	// Close the remaining ends of the pipe in the parent process
	close(pipefd[0]);
	close(pipefd[1]);

	// Wait for both child processes to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// Return the result of the second child process (cmd2)
	if (WIFEXITED(status2))
		return WEXITSTATUS(status2);

	return 1;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (level < 0)
		return shell_exit();

	if (c == NULL)
		return shell_exit();

	if (c->op == OP_NONE)
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level + 1, c);

	int value = 0;
	int value_cmd1;
	int value_cmd2;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		value_cmd1 = parse_command(c->cmd1, level + 1, c);
		value_cmd2 = parse_command(c->cmd2, level + 1, c);

		value = value_cmd1 | value_cmd2;
		return value;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		value = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		return value;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		value_cmd1 = parse_command(c->cmd1, level + 1, c);

		if (value_cmd1 != 0)
			value = parse_command(c->cmd2, level + 1, c);
		else
			value = value_cmd1;
		return value;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		value_cmd1 = parse_command(c->cmd1, level + 1, c);

		if (value_cmd1 == 0)
			value = parse_command(c->cmd2, level + 1, c);
		else
			value = value_cmd1;
		return value;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		value = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		return value;

	default:
		return SHELL_EXIT;
	}

/* TODO: Replace with actual exit code of command. */
}
