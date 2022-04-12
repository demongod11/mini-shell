# include <stddef.h>
# include <sys/stat.h>
# include <stdlib.h>
# include <unistd.h>
# include <limits.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdio.h>

#define SHELL_PROMPT			"\e[32mcs242_mini_shell> \e[0m"
#define BACK_CURSOR			"\033[2D"
#define CLEAR_FROM_CURSOR		"\033[0K"
#define STATUS_SYNTAX_ERROR		258
#define STATUS_TOKEN_ERROR			2
#define STATUS_CMD_NOT_FOUND		127
#define STATUS_CMD_NOT_EXECUTABLE	126
#define MY_LONG_MAX 9223372036854775807
#define GNL_BUFFER_SIZE 1024
#define REDIR_FD_NOT_SPECIFIED		-1
#define REDIR_FD_OUT_OF_RANGE		-2
#define NO_PID						-1
#define PIPE_IN					1
#define PIPE_OUT					0
#define FILE_MODE	0644
#define NOW 0
#define LAST 1
#define EXPANDED 2
#define RES_LIST 3
#define VAR_NAME 0
#define VALUE 1
#define TMP 2
#define RES 3
#define DOT_FILE_NAME	"ast.dot"
#define DOT_INDENT		"    "

# ifndef DEBUG
#  define DEBUG			0
# endif
# ifndef LEAKS
#  define LEAKS			0
# endif

# if LEAKS                                             

void			end(void) __attribute__((destructor));

# endif

// In this program many of the inbuilt c functions like atoi(), itoa(), strlen() etc
// has been rebuilt with modifications

typedef struct	s_list
{
	void			*content;
	struct s_list	*next;
}				t_list;

typedef enum	e_bool
{
	FALSE,
	TRUE
}				t_bool;

size_t	cs242_strlen(const char *s)           //This function is the modification of standard strlen() function
{
	size_t i;

	if (!s)
		return (0);
	i = 0;
	while (s[i] != '\0')
		i++;
	return (i);
}

void	cs242_putstr_fd(char *s, int fd)
{
	if (!s)
		return ;
	write(fd, s, cs242_strlen(s));
}

void	cs242_putendl_fd(char *s, int fd)
{
	if (!s)
		return ;
	write(fd, s, cs242_strlen(s));
	write(fd, "\n", 1);
}

void	cs242_safe_free_char(char **target)
{
	free(*target);
	*target = NULL;
}

char	*cs242_strjoin(char const *s1, char const *s2)    // This function is used to concatenate to strings
{
	char	*result;
	int		i;
	size_t	len;

	len = 1;
	i = 0;
	len += cs242_strlen(s1);
	len += cs242_strlen(s2);
	if (!(result = malloc(sizeof(char) * len)))
		return (NULL);
	while (s1 && *s1)
		result[i++] = *s1++;
	while (s2 && *s2)
		result[i++] = *s2++;
	result[i] = '\0';
	return (result);
}

static int	free_all(char *storage, char *buf, char *line)    // This function is very very important
{                                                             // It frees all the memory allocated to the pointers
	free(buf);                                                // If this is not done then "MEMORY LEAK" happens
	free(storage);
	free(line);
	return (-1);
}

char	*cs242_find_new_line(const char *s, size_t len)
{
	size_t i;

	if (!s)
		return (NULL);
	i = 0;
	while (s[i] != '\n')
	{
		if (!(i < len))
			return (NULL);
		i++;
	}
	return ((char *)&s[i]);
}

static int	success_gnl(char *nl_p, char **storage, char *buf, char **line)
{
	char *tmp;

	tmp = NULL;
	*nl_p = '\0';
	if (!(*line = cs242_strjoin(*storage, buf)))
		return (free_all(*storage, buf, *line));
	tmp = *storage;
	if (!(*storage = cs242_strjoin((nl_p + 1), NULL)))
		return (free_all(tmp, buf, *line));
	cs242_safe_free_char(&tmp);
	cs242_safe_free_char(&buf);
	return (1);
}
static int	finish_gnl(char **storage, char *buf, char **line)
{
	if (!(*line = cs242_strjoin(*storage, buf)))
		return (free_all(*storage, buf, *line));
	cs242_safe_free_char(storage);
	cs242_safe_free_char(&buf);
	return (0);
}
static int	loop_gnl(int fd, char **storage, char *buf, char **line)
{
	char		*tmp;
	ssize_t		read_len;

	while (1)
	{
		read_len = read(fd, buf, GNL_BUFFER_SIZE);
		if (read_len < 0)
			return (free_all(*storage, buf, *line));
		buf[read_len] = '\0';
		if (read_len < GNL_BUFFER_SIZE)
		{
			if ((tmp = cs242_find_new_line(buf, read_len)))
				return (success_gnl(tmp, storage, buf, line));
			else
				return (finish_gnl(storage, buf, line));
		}
		if ((tmp = cs242_find_new_line(buf, GNL_BUFFER_SIZE)))
			return (success_gnl(tmp, storage, buf, line));
		if (!(tmp = cs242_strjoin(*storage, buf)))
			return (free_all(*storage, buf, *line));
		cs242_safe_free_char(storage);
		*storage = tmp;
	}
}

int			cs242_get_next_line(int fd, char **line)
{
	static char	*storage;
	char		*buf;
	char		*tmp;

	buf = NULL;
	if (!line || fd < 0 || GNL_BUFFER_SIZE <= 0)
		return (free_all(storage, buf, NULL));
	*line = NULL;
	if (storage && (tmp = cs242_find_new_line(storage, cs242_strlen(storage))))
		return (success_gnl(tmp, &storage, buf, line));
	if (!(buf = malloc(GNL_BUFFER_SIZE + 1)))
		return (free_all(storage, buf, *line));
	return (loop_gnl(fd, &storage, buf, line));
}

int	cs242_strcmp(char *s1, char *s2)                  // This function is a modification of the standard strcmp() function
{                                                     // It compares 2 strings and returns appropriate values
	int i;                                            // Based on the return values we decide the relation between the 2 strings

	i = 0;
	while (1)
	{
		if ((s1[i] - s2[i]) != 0)
		{
			return (s1[i] - s2[i]);
		}
		if (!(s1[i]) && !(s2[i]))
			break ;
		i++;
	}
	return (0);
}


typedef enum	e_tokentype{
	CHAR_GENERAL = -1,
	CHAR_PIPE = '|',
	CHAR_QOUTE = '\'',
	CHAR_DQUOTE = '\"',
	CHAR_SEMICOLON = ';',
	CHAR_WHITESPACE = ' ',
	CHAR_ESCAPE = '\\',
	CHAR_GREATER = '>',
	CHAR_LESSER = '<',
	CHAR_TAB = '\t',
	CHAR_NULL = 0,
	D_SEMICOLON = -4,
	D_GREATER = -3,
	IO_NUMBER = -2,
	TOKEN = -1,
}				t_token_type;

typedef enum	e_token_state{
	STATE_IN_DQUOTE,
	STATE_IN_QUOTE,
	STATE_GENERAL,
}				t_token_state;

typedef struct s_token	t_token;

struct			s_token
{
	t_token			*next;
	t_token			*prev;
	t_token_type	type;
	char			*data;
};

size_t			calc_tokens_len(t_token *tokens);
t_token			*token_init(size_t len, t_token *prev);
t_token			*find_last_token(t_token *tokens);
t_token_type	judge_token_type(char c);
void			del_token(t_token **token_p);
void			del_token_list(t_token **token_p);
void			token_join(t_token *prev_token, t_token *next_token);

typedef struct	s_env
{
	char			*name;
	char			*value;
	t_bool			is_env;
	struct s_env	*next;
}				t_env;

typedef struct stat	t_stat;

void			error_exit(char *command);
void			print_error(char *message, char *command);
void			print_syntax_error(t_token *token);
void			print_token_error(t_token_state state);
void			print_bad_fd_error(int fd);
void			print_numeric_argument_error(char *arg);
void			print_error_filename(char *message,
					char *command, char *file);
void			print_identifier_error(char *command, char *name);

t_env			*create_envs_from_environ(void);
char			**generate_environ(t_env *envs);
t_bool			can_generate_environ(t_env *env);
void			add_env(t_env **envs, t_env *new_env);
void			del_env(t_env **envs, char *name);
t_env			*copy_envs(t_env *envs);

t_env			*get_last_env(t_env *envs);
size_t			get_environ_size(t_env *envs);
t_env			*create_new_env(char *env_str);
const char		*get_env_data(char *name);
t_env			*get_env(const char *name);

void			env_mergesort(t_env **lst, int (*cmp)());
void			shlvl_init(void);
char			*join_path(const char *prev, const char *next);
char			*path_canonicalisation(char *path);
char			**get_colon_units(const char *str, const char *subst);
t_bool			is_digit_str(char *str);
t_bool			is_directory(const char *path);
void			update_env_value(const char *env_name, const char *new_value,
					t_bool is_env_var, t_bool append_flag);

void			set_signal_handler(void (*func)(int));
void			handle_signal(int signal);

typedef struct	s_tokeniser{
	size_t			str_i;
	size_t			tok_i;
	size_t			str_len;
	t_bool			esc_flag;
	t_bool			is_quoted;
	t_token			*token;
	t_token			*tokens_start;
	t_token_state	state;
	char			*quote_start;
}				t_tokeniser;

t_token			*tokenise(char *input, t_bool esc_flag);
t_bool			is_normal_token(t_token *token);
t_bool			is_io_number_token(t_tokeniser *toker, t_token_type type);
void			general_state(t_tokeniser *t, t_token_type y, char *s);
void			quote_state(t_tokeniser *t, t_token_type y, char *s);
void			d_quote_state(t_tokeniser *t, t_token_type y, char *s);
void			tokeniser_add_new_token(t_tokeniser *toker);
void			print_token_list(t_token *tokens, t_bool esc_flag);

typedef struct s_node	t_node;

typedef enum			e_redirect_type
{
	REDIR_INPUT,
	REDIR_OUTPUT,
	REDIR_APPEND_OUTPUT
}						t_redirect_type;

typedef struct			s_redirect
{
	int					fd_io;
	int					fd_file;
	int					fd_backup;
	t_redirect_type		type;
	t_token				*filename;
	struct s_redirect	*next;
	struct s_redirect	*prev;
}						t_redirect;

typedef struct			s_command
{
	t_token				*args;
	t_redirect			*redirects;
	pid_t				pid;
	struct s_command	*next;
}						t_command;

typedef enum			e_pipe_state
{
	NO_PIPE,
	PIPE_READ_ONLY,
	PIPE_WRITE_ONLY,
	PIPE_READ_WRITE
}						t_pipe_state;

typedef enum			e_cmd_type
{
	ABSOLUTE,
	RELATIVE,
	COMMAND
}						t_cmd_type;

void					create_pipe(t_pipe_state state, int new_pipe[]);
void					dup_pipe(t_pipe_state state, int old_pipe[],
							int new_pipe[]);
void					cleanup_pipe(t_pipe_state state, int old_pipe[],
							int new_pipe[]);

t_bool					setup_redirects(t_command *command);
t_bool					dup_redirects(t_command *command, t_bool is_parent);
void					cleanup_redirects(t_command *command);

t_bool					convert_tokens(t_command *command, char ***args);
void					wait_commands(t_command *command);
void					handle_execve_error(char *path);

char					*build_cmd_path(const char *cmd);

t_bool					is_executable(const char *path);
t_bool					is_command_exist(const char *path, char **res);

typedef enum	e_node_type
{
	NODE_COMMAND,
	NODE_PIPE,
	NODE_SEMICOLON,
}				t_node_type;

typedef struct	s_node
{
	t_node_type		type;
	t_command		*command;
	struct s_node	*left;
	struct s_node	*right;
}				t_node;

typedef struct	s_parse_info
{
	t_command		*last_command;
}				t_parse_info;

t_bool			parse_complete_command(t_node **nodes, t_token **tokens);
void			add_copied_token(t_token **list, t_token *original_token);
t_bool			has_token_type(t_token **token, t_token_type type);
t_bool			is_redirect_token(t_token *token);

t_node			*add_parent_node(t_node_type type, t_node *left, t_node *right);
t_node			*create_command_node(t_parse_info *info);
void			set_command_args(t_command *command, t_token **tokens);
void			del_node_list(t_node **node);

void			print_nodes(t_node *node);
void			print_command_args(t_token *args, int fd);
void			print_node_label(t_node *node, int fd);

t_redirect		*create_redirect(void);
void			add_redirect(t_redirect **list, t_redirect *new);
t_bool			set_redirect_type(t_token *token, t_redirect *redirect);
void			del_redirect_list(t_redirect **redirect_p);

typedef struct	s_expander
{
	size_t			str_i;
	t_token_state	state;
	t_token_type	type;
	char			*str;
}				t_expander;

void			expand_tokens(t_token **tokens);
char			*create_expanded_str(const char *str, t_token_state state,
					t_bool is_env);
char			*expand_env_var(char *input);
char			*dup_env_value(char *name);

int		exec_pwd(void)                                 // This function implements the pwd internal command
{
	extern char *g_pwd;

	cs242_putendl_fd(g_pwd, STDOUT_FILENO);
	return (EXIT_SUCCESS);
}
void	cs242_putchar_fd(char c, int fd)              // This function is a modification of the standard putchar() function
{
	char c1;
	char c2;

	if ((unsigned char)c <= 127)
		write(fd, &c, 1);
	else
	{
		c1 = ((unsigned char)c >> 6) | 0b11000000;
		c2 = ((unsigned char)c & 0b00111111) | 0b10000000;
		write(fd, &c1, 1);
		write(fd, &c2, 1);
	}
}

static void	print_env(t_env *env)
{
	char	*escaped_value;

	if (env->is_env == FALSE)
		return ;
	cs242_putstr_fd("declare -x ", STDOUT_FILENO);
	cs242_putstr_fd(env->name, STDOUT_FILENO);
	if (env->value)
	{
		escaped_value = create_expanded_str(env->value, STATE_IN_DQUOTE, TRUE);
		cs242_putstr_fd("=\"", STDOUT_FILENO);
		cs242_putstr_fd(escaped_value, STDOUT_FILENO);
		cs242_putchar_fd('"', STDOUT_FILENO);
		free(escaped_value);
	}
	cs242_putchar_fd('\n', STDOUT_FILENO);
}
int			exec_env(void)                          // This function implements the env internal command
{
	extern t_env	*g_envs;
	t_env			*env;

	env = g_envs;
	while (env)
	{
		print_env(env);
		env = env->next;
	}
	return (EXIT_SUCCESS);
}
char	*cs242_strchr(const char *s, int c)
{
	int i;

	i = 0;
	while (s[i] != (char)c)
	{
		if (s[i] == '\0')
			return (NULL);
		i++;
	}
	return ((char *)&s[i]);
}
static void		separate_arg(char *arg, char **sep, char **value,
	t_bool *append_flag)
{
	*sep = cs242_strchr(arg, '=');
	if (*sep)
	{
		**sep = '\0';
		if (*sep != arg && *(*sep - 1) == '+')
		{
			*(*sep - 1) = '\0';
			*append_flag = TRUE;
		}
		*value = *sep + 1;
	}
	else
		*value = NULL;
}
int	cs242_isalpha(int c)                   //  This function is for finding whether a character is alphabet or not
{
	if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z'))
		return (1);
	return (0);
}
int	cs242_isalnum(int c)
{
	if (('0' <= c && c <= '9') ||
	('A' <= c && c <= 'Z') ||
	('a' <= c && c <= 'z'))
		return (1);
	return (0);
}
t_bool			is_identifier(char *name)
{
	size_t	i;

	i = 0;
	if (name[i] != '_' && !cs242_isalpha(name[i]))
		return (FALSE);
	i++;
	while (name[i])
	{
		if (name[i] != '_' && !cs242_isalnum(name[i]))
			return (FALSE);
		i++;
	}
	return (TRUE);
}
static void		restore_arg(char *sep, t_bool append_flag)
{
	if (sep)
	{
		*sep = '=';
		if (append_flag == TRUE)
			*(sep - 1) = '+';
	}
}
static int		set_envs(char **args)
{
	size_t	i;
	char	*sep;
	char	*value;
	t_bool	append_flag;
	int		ret;

	ret = EXIT_SUCCESS;
	i = 1;
	value = NULL;
	while (args[i])
	{
		append_flag = FALSE;
		separate_arg(args[i], &sep, &value, &append_flag);
		if (is_identifier(args[i]))
			update_env_value(args[i], value, TRUE, append_flag);
		else
		{
			restore_arg(sep, append_flag);
			print_identifier_error("export", args[i]);
			ret = EXIT_FAILURE;
		}
		i++;
	}
	return (ret);
}
static int	compare_env(t_env *left, t_env *right)
{
	return (cs242_strcmp(left->name, right->name));
}
int			print_envs(void)
{
	extern t_env	*g_envs;
	t_env			*envs;
	t_env			*tmp;

	envs = copy_envs(g_envs);
	env_mergesort(&envs, compare_env);
	while (envs)
	{
		print_env(envs);
		tmp = envs->next;
		free(envs);
		envs = tmp;
	}
	return (EXIT_SUCCESS);
}
int				exec_export(char **args)       // This function implements the export internal command
{
	if (args[1])
	{
		return (set_envs(args));
	}
	else
	{
		return (print_envs());
	}
	return (EXIT_SUCCESS);
}
int	exec_unset(char **args)                    // This function implements the unset internal command
{
	extern t_env	*g_envs;
	size_t			i;
	int				ret;

	i = 1;
	ret = EXIT_SUCCESS;
	while (args[i])
	{
		if (is_identifier(args[i]) == TRUE)
		{
			del_env(&g_envs, args[i]);
		}
		else
		{
			print_identifier_error("unset", args[i]);
			ret = EXIT_FAILURE;
		}
		i++;
	}
	return (ret);
}
static t_bool	is_out_of_range(unsigned long *value, int sign, char numchar)   // This function is used to check whether an int or char are in range or not
{
	unsigned long	ov_div;

	ov_div = MY_LONG_MAX / 10;
	if ((ov_div < *value || (ov_div == *value && numchar > '7')) && sign > 0)
	{
		*value = MY_LONG_MAX;
		return (TRUE);
	}
	if ((ov_div < *value || (ov_div == *value && numchar > '8'))
	&& sign == -1)
	{
		*value = MY_LONG_MAX * -1 - 1;
		return (TRUE);
	}
	return (FALSE);
}
int				cs242_atoi(const char *str)              // This function is the modification of the standard atoi() function
{                                                        // It takes string as argument and converts it to an integer appropriately 
	int				i;
	int				sign;
	unsigned long	result;

	i = 0;
	result = 0;
	while ((9 <= str[i] && str[i] <= 13) || str[i] == 32)
		i++;
	sign = str[i] == '-' ? -1 : 1;
	if (str[i] == '-' || str[i] == '+')
		i++;
	while (str[i] && ('0' <= str[i] && str[i] <= '9'))
	{
		if (is_out_of_range(&result, sign, str[i]) == TRUE)
		{
			errno = ERANGE;
			return ((int)result);
		}
		result *= 10;
		result += str[i++] - '0';
	}
	return ((int)result * sign);
}
static t_bool	has_error(char **args, int index)
{
	if (errno || is_digit_str(args[index]) == FALSE)
	{
		print_numeric_argument_error(args[index]);
		exit(255);
	}
	if (args[index + 1])
	{
		print_error("too many arguments", "exit");
		return (TRUE);
	}
	return (FALSE);
}
int				exec_exit(char **args)                  // This function implements the exit internal command
{
	extern int		g_status;
	extern t_bool	g_interactive;
	extern t_bool	g_exited;
	int				i;
	int				status;

	i = 1;
	if (g_interactive == TRUE)
		cs242_putendl_fd("exit", STDERR_FILENO);	remove("/tmp/history.txt");
	if (args[i] && cs242_strcmp(args[i], "--") == 0)
		i++;
	if (args[i] == NULL)
		exit(g_status);
	errno = 0;
	status = cs242_atoi(args[i]);
	if (has_error(args, i) == FALSE)
		exit(status);
	g_exited = TRUE;
	return (EXIT_FAILURE);
}
const char	*set_cd_destination(char **args)
{
	t_env	*home_env;
	size_t	index;

	index = 0;
	while (args[index])
		index++;
	if (index == 1)
	{
		if (!(home_env = get_env("HOME")))
		{
			print_error("HOME not set", "cd");
			return (NULL);
		}
		if (!home_env->value)
			return ("");
		return (home_env->value);
	}
	return (args[1]);
}
int	cs242_strncmp(const char *s1, const char *s2, size_t n)
{
	size_t			i;
	unsigned char	*casted_s1;
	unsigned char	*casted_s2;

	i = 0;
	casted_s1 = (unsigned char *)s1;
	casted_s2 = (unsigned char *)s2;
	if (n == 0)
		return (0);
	while (1)
	{
		if ((casted_s1[i] - casted_s2[i]) != 0)
			return (casted_s1[i] - casted_s2[i]);
		i++;
		if ((!(casted_s1[i]) && !(casted_s2[i])) || i == n)
			break ;
	}
	return (0);
}
t_bool		needs_env_path_search(char **args, const char *dest)
{
	if (args[1] == NULL || args[1][0] == '/')
		return (FALSE);
	if (cs242_strcmp((char *)dest, ".") == 0 ||
		cs242_strcmp((char *)dest, "..") == 0 ||
		cs242_strncmp((char *)dest, "./", 2) == 0 ||
		cs242_strncmp((char *)dest, "../", 3) == 0)
	{
		return (FALSE);
	}
	return (TRUE);
}
void	cs242_safe_free_split(char ***target)
{
	size_t index;

	index = 0;
	if (!*target)
		return ;
	while ((*target)[index])
	{
		free((*target)[index]);
		(*target)[index] = NULL;
		index++;
	}
	free(*target);
	*target = NULL;
}
char	*cs242_strdup(const char *s1)               // This function is the modification of the standars strdup() function
{
	char	*result;
	int		i;

	i = 0;
	while (s1[i])
		i++;
	i++;
	result = (char *)malloc(sizeof(char) * i);
	if (result == NULL)
		return (NULL);
	i = 0;
	while (s1[i])
	{
		result[i] = s1[i];
		i++;
	}
	result[i] = '\0';
	return (result);
}
char	*set_cd_path(const char *arg, t_bool *is_canon_path)
{
	char		*canon_path;
	char		*physical_path;
	extern char *g_pwd;

	if (*arg == '/')
		physical_path = cs242_strdup(arg);
	else
		physical_path = join_path(g_pwd, arg);
	if (!physical_path)
		error_exit(NULL);
	canon_path = path_canonicalisation(physical_path);
	if (canon_path)
	{
		cs242_safe_free_char(&physical_path);
		*is_canon_path = TRUE;
		return (canon_path);
	}
	else
	{
		cs242_safe_free_char(&canon_path);
		*is_canon_path = FALSE;
		return (physical_path);
	}
}
char	*get_cwd_path(char *caller)                      // This function is used to get the current working directory path
{ 
	char *cwd;

	cwd = getcwd(0, 0);
	if (!cwd)
	{
		cs242_putstr_fd(caller, STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
		cs242_putstr_fd("error retrieving current directory", STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
		cs242_putstr_fd("getcwd: cannot access parent directories", STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
		cs242_putstr_fd(strerror(errno), STDERR_FILENO);
		cs242_putstr_fd("\n", STDERR_FILENO);
	}
	return (cwd);
}
char	*get_new_pwd(char *path, t_bool is_canon_path, t_bool is_abs_path)  //This function is used to get the new present working directory
{
	char *new_pwd;

	new_pwd = NULL;
	if (is_abs_path)
	{
		if (is_canon_path == FALSE)
			new_pwd = get_cwd_path("cd");
		if (is_canon_path || new_pwd == NULL)
		{
			if (!(new_pwd = cs242_strdup(path)))
				error_exit(NULL);
		}
	}
	else
	{
		if (!(new_pwd = get_cwd_path("cd")))
		{
			if (!(new_pwd = cs242_strdup(path)))
				error_exit(NULL);
		}
	}
	return (new_pwd);
}
int		change_dir_process(char *cd_path, const char *arg, t_bool is_canon_path)
{
	int			res;
	int			err;
	extern char	*g_pwd;

	res = chdir(cd_path);
	if (res == 0)
	{
		cs242_safe_free_char(&g_pwd);
		g_pwd = get_new_pwd(cd_path, is_canon_path, TRUE);
		return (res);
	}
	err = errno;
	res = chdir(arg);
	if (res == 0)
	{
		cs242_safe_free_char(&g_pwd);
		g_pwd = get_new_pwd(cd_path, is_canon_path, FALSE);
		return (res);
	}
	errno = err;
	res = EXIT_FAILURE;
	return (res);
}
t_bool	try_change_dir(const char *destination)
{
	char		*path;
	t_bool		is_canon_path;
	int			res;

	path = set_cd_path(destination, &is_canon_path);
	res = change_dir_process(path, destination, is_canon_path);
	cs242_safe_free_char(&path);
	if (res == 0)
		return (TRUE);
	return (FALSE);
}
char		*try_splitted_env_path(char **split_env, const char *dest)
{
	size_t		index;
	char		*joined_dest;

	index = 0;
	joined_dest = NULL;
	while (split_env[index])
	{
		if (cs242_strlen(split_env[index]) == 0)
		{
			if (!(joined_dest = cs242_strdup(dest)))
				error_exit(NULL);
		}
		else
			joined_dest = join_path(split_env[index], dest);
		if (try_change_dir(joined_dest))
			break ;
		cs242_safe_free_char(&joined_dest);
		index++;
	}
	cs242_safe_free_char(&joined_dest);
	if (split_env[index])
		return (split_env[index]);
	return (NULL);
}

t_bool		try_env_path(const char *dest)
{
	char		**split_env;
	t_bool		res;
	char		*try_chdir_res;
	extern char	*g_pwd;

	res = FALSE;
	if (!(split_env = get_colon_units(get_env_data("CDPATH"), "")))
		error_exit(NULL);
	try_chdir_res = try_splitted_env_path(split_env, dest);
	if (try_chdir_res)
		res = TRUE;
	if (res && cs242_strlen(try_chdir_res) != 0)
		cs242_putendl_fd(g_pwd, STDOUT_FILENO);
	cs242_safe_free_split(&split_env);
	return (res);
}
void	bind_pwd_value(void)
{
	extern char *g_pwd;

	update_env_value("OLDPWD", get_env_data("PWD"), FALSE, FALSE);
	update_env_value("PWD", g_pwd, FALSE, FALSE);
}
int			exec_cd(char **args)
{
	const char	*dest;
	extern char *g_pwd;

	if (!(dest = set_cd_destination(args)))
		return (EXIT_FAILURE);
	if (needs_env_path_search(args, dest))
	{
		if (try_env_path(dest))
		{
			bind_pwd_value();
			return (EXIT_SUCCESS);
		}
	}
	if (try_change_dir(dest))
	{
		bind_pwd_value();
		return (EXIT_SUCCESS);
	}
	print_error_filename(strerror(errno), "cd", (char *)dest);
	return (EXIT_FAILURE);
}
t_bool	is_option_str(char *str)
{
	size_t len;

	if (!str)
		return (FALSE);
	len = cs242_strlen(str);
	if (len < 2 || str[0] != '-' || str[1] != 'n')
		return (FALSE);
	str++;
	while (*str == 'n')
		str++;
	if (*str == '\0')
		return (TRUE);
	return (FALSE);
}
void	skip_option(char **args, t_bool *flag, size_t *index)
{
	while (args[*index])
	{
		if (is_option_str(args[*index]))
			*flag = TRUE;
		else
			break ;
		*index += 1;
	}
}
int		exec_echo(char **args)                // This function is used to implement the echo internal command
{
	size_t index;
	t_bool option_flag;

	index = 1;
	option_flag = FALSE;
	skip_option(args, &option_flag, &index);
	while (args[index])
	{
		cs242_putstr_fd(args[index], STDOUT_FILENO);
		if (args[index + 1] != NULL)
			cs242_putstr_fd(" ", STDOUT_FILENO);
		index++;
	}
	if (option_flag == FALSE)
		cs242_putstr_fd("\n", STDOUT_FILENO);
	return (EXIT_SUCCESS);
}

int		exec_builtin(char **args)                    // This function calls in most of the internal commands
{
	if (cs242_strcmp(args[0], "exit") == 0)
		return (exec_exit(args));
	if (cs242_strcmp(args[0], "cd") == 0)
		return (exec_cd(args));
	if (cs242_strcmp(args[0], "echo") == 0)
		return (exec_echo(args));
	if (cs242_strcmp(args[0], "pwd") == 0)
		return (exec_pwd());
	if (cs242_strcmp(args[0], "env") == 0)
		return (exec_env());
	if (cs242_strcmp(args[0], "export") == 0)
		return (exec_export(args));
	if (cs242_strcmp(args[0], "unset") == 0)
		return (exec_unset(args));
	return (EXIT_FAILURE);
}

int		is_builtin(char **args)                   // This function checks if a process is built in or not
{
	const char	*commands[] = {
		"exit", "cd", "echo", "pwd", "env", "export", "unset", NULL
	};
	int			i;

	i = 0;
	if (args[0] == NULL)
		return (0);
	while (commands[i])
	{
		if (cs242_strcmp(args[0], (char *)commands[i]) == 0)
			return (1);
		i++;
	}
	return (0);
}
t_bool		is_executable(const char *path)    // This function checks if a process is executable or not
{
	t_stat	path_stat;

	if (stat(path, &path_stat) == -1)
		return (FALSE);
	if ((path_stat.st_mode & S_IXUSR) != S_IXUSR)
		return (FALSE);
	if ((path_stat.st_mode & S_IRUSR) != S_IRUSR)
		return (FALSE);
	return (TRUE);
}

t_bool		is_command_exist(const char *path, char **res)
{
	t_stat buf;

	if (!path)
		return (FALSE);
	if (lstat(path, &buf) == -1)
		return (FALSE);
	if (S_ISDIR(buf.st_mode))
		return (FALSE);
	cs242_safe_free_char(res);
	if (!(*res = cs242_strdup(path)))
		error_exit(NULL);
	return (TRUE);
}

t_cmd_type	judge_cmd_type(const char *str)
{
	if (*str == '/')
		return (ABSOLUTE);
	else if (cs242_strchr(str, '/') != NULL)
		return (RELATIVE);
	else
		return (COMMAND);
}

void		try_search_command(char **split_path, char **res, const char *cmd)
{
	int		index;
	char	*path;

	index = 0;
	path = NULL;
	while (split_path[index])
	{
		cs242_safe_free_char(&path);
		path = join_path(split_path[index], cmd);
		if (is_command_exist(path, res) && !is_directory(path) &&
			is_executable(path))
			break ;
		index++;
	}
	cs242_safe_free_char(&path);
}

char		*search_command_binary(const char *cmd)
{
	char		**split_path;
	char		*res;
	const char	*env_value;

	res = NULL;
	env_value = get_env_data("PATH");
	if (cs242_strcmp((char *)env_value, "") == 0)
	{
		if (!(res = cs242_strdup(cmd)))
			error_exit(NULL);
		return (res);
	}
	if (!(split_path = get_colon_units(env_value, ".")))
		error_exit(NULL);
	try_search_command(split_path, &res, cmd);
	cs242_safe_free_split(&split_path);
	return (res);
}

static void	check_cmd_path(const char *cmd, const char *path)
{
	if (path == NULL)
	{
		print_error("command not found", (char *)cmd);
		exit(STATUS_CMD_NOT_FOUND);
	}
}

char		*build_cmd_path(const char *cmd)
{
	t_cmd_type	type;
	char		*res;

	if (!cmd)
		return (NULL);
	type = judge_cmd_type(cmd);
	if (type == COMMAND)
	{
		res = search_command_binary(cmd);
	}
	else
	{
		if (!(res = cs242_strdup(cmd)))
			error_exit(NULL);
	}
	check_cmd_path(cmd, res);
	return (res);
}

static char	**convert_args(t_command *command)
{
	char	**args;
	t_token	*now_token;
	size_t	len;
	size_t	i;

	len = 0;
	now_token = command->args;
	while (now_token)
	{
		now_token = now_token->next;
		len++;
	}
	if (!(args = (char **)malloc(sizeof(char *) * (len + 1))))
		error_exit(NULL);
	now_token = command->args;
	i = 0;
	while (now_token)
	{
		if (!(args[i] = cs242_strdup(now_token->data)))
			error_exit(NULL);
		now_token = now_token->next;
		i++;
	}
	args[i] = NULL;
	return (args);
}

t_bool		convert_tokens(t_command *command, char ***args)
{
	expand_tokens(&command->args);
	*args = convert_args(command);
	if (*args[0] == NULL)
	{
		return (FALSE);
	}
	return (TRUE);
}

static void	handle_command_status(int status, t_bool catch_sigint)
{
	extern int	g_status;
	int			signal;

	if (WIFEXITED(status))
		g_status = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
	{
		signal = WTERMSIG(status);
		if (signal == SIGQUIT)
			cs242_putendl_fd("Quit: 3", STDERR_FILENO);
		g_status = signal + 128;
	}
	if (catch_sigint)
		cs242_putendl_fd("", STDERR_FILENO);
}

void		wait_commands(t_command *command)
{
	extern int	g_status;
	int			status;
	t_bool		has_child;
	t_bool		catch_sigint;

	has_child = FALSE;
	catch_sigint = FALSE;
	while (command)
	{
		if (command->pid != NO_PID)
		{
			if (waitpid(command->pid, &status, 0) < 0)
				error_exit(NULL);
			if (WIFSIGNALED(status) && WTERMSIG(status) == SIGINT)
				catch_sigint = TRUE;
			has_child = TRUE;
		}
		command = command->next;
	}
	if (has_child == FALSE)
		return ;
	handle_command_status(status, catch_sigint);
}

void		handle_execve_error(char *path)
{
	int	status;

	if (errno == ENOENT)
		status = STATUS_CMD_NOT_FOUND;
	else
		status = STATUS_CMD_NOT_EXECUTABLE;
	if (is_directory(path))
	{
		print_error("is a directory", path);
		exit(status);
	}
	if (errno == ENOEXEC && !is_executable(path))
		errno = EACCES;
	if (errno == ENOEXEC)
		exit(EXIT_SUCCESS);
	print_error(strerror(errno), path);
	exit(status);
}
static void		exec_binary(char **args)
{
	extern t_env	*g_envs;
	char			**envs;
	char			*path;

	envs = generate_environ(g_envs);
	path = build_cmd_path(args[0]);
	if (execve(path, args, generate_environ(g_envs)) < 0)
	{
		handle_execve_error(path);
	}
	free(path);
	cs242_safe_free_split(&envs);
}

static int		exec_builtin_parent(t_command *command, char **args)
{
	if (setup_redirects(command) == FALSE)
		return (EXIT_FAILURE);
	if (dup_redirects(command, TRUE) == FALSE)
		return (EXIT_FAILURE);
	return (exec_builtin(args));
}

static void		exec_command_child(
	t_command *command, char **args, t_pipe_state state, int old_pipe[])
{
	pid_t	pid;
	int		new_pipe[2];

	create_pipe(state, new_pipe);
	if ((pid = fork()) < 0)
		error_exit(NULL);
	if (pid == 0)
	{
		set_signal_handler(SIG_DFL);
		if (setup_redirects(command) == FALSE)
			exit(EXIT_FAILURE);
		if (args[0] == NULL)
			exit(EXIT_SUCCESS);
		dup_pipe(state, old_pipe, new_pipe);
		if (dup_redirects(command, FALSE) == FALSE)
			exit(EXIT_FAILURE);
		if (is_builtin(args))
			exit(exec_builtin(args));
		else
			exec_binary(args);
	}
	set_signal_handler(SIG_IGN);
	cleanup_pipe(state, old_pipe, new_pipe);
	command->pid = pid;
}

static void		update_pipe_state(t_command *command, t_pipe_state *state)
{
	if (*state == NO_PIPE)
		return ;
	if (command->next && command->next->next)
		*state = PIPE_READ_WRITE;
	else
		*state = PIPE_READ_ONLY;
}

int				exec_command(
	t_command *command, t_pipe_state *state, int old_pipe[])
{
	char	**args;
	int		status;

	status = EXIT_SUCCESS;
	convert_tokens(command, &args);
	if (*state == NO_PIPE && is_builtin(args))
		status = exec_builtin_parent(command, args);
	else
		exec_command_child(command, args, *state, old_pipe);
	cleanup_redirects(command);
	update_pipe_state(command, state);
	cs242_safe_free_split(&args);
	return (status);
}
static t_bool	can_write(t_pipe_state state)
{
	if (state == PIPE_WRITE_ONLY || state == PIPE_READ_WRITE)
	{
		return (TRUE);
	}
	return (FALSE);
}

static t_bool	can_read(t_pipe_state state)
{
	if (state == PIPE_READ_ONLY || state == PIPE_READ_WRITE)
	{
		return (TRUE);
	}
	return (FALSE);
}

void			create_pipe(t_pipe_state state, int new_pipe[])
{
	if (can_write(state) == TRUE)
	{
		if (pipe(new_pipe) < 0)
		{
			error_exit(NULL);
		}
	}
}

void			dup_pipe(t_pipe_state state, int old_pipe[], int new_pipe[])
{
	if (can_read(state) == TRUE)
	{
		if (close(old_pipe[PIPE_IN]) < 0 ||
			dup2(old_pipe[PIPE_OUT], STDIN_FILENO) < 0 ||
			close(old_pipe[PIPE_OUT]) < 0)
		{
			error_exit(NULL);
		}
	}
	if (can_write(state) == TRUE)
	{
		if (close(new_pipe[PIPE_OUT]) < 0 ||
			dup2(new_pipe[PIPE_IN], STDOUT_FILENO) < 0 ||
			close(new_pipe[PIPE_IN]) < 0)
		{
			error_exit(NULL);
		}
	}
}

void			cleanup_pipe(t_pipe_state state, int old_pipe[], int new_pipe[])
{
	if (can_read(state) == TRUE)
	{
		if (close(old_pipe[PIPE_OUT]) < 0 || close(old_pipe[PIPE_IN]) < 0)
		{
			error_exit(NULL);
		}
	}
	if (can_write(state) == TRUE)
	{
		old_pipe[PIPE_OUT] = new_pipe[PIPE_OUT];
		old_pipe[PIPE_IN] = new_pipe[PIPE_IN];
	}
}

static int		open_file(t_redirect *redir)
{
	char *filename;

	filename = redir->filename->data;
	if (redir->type == REDIR_INPUT)
		return (open(filename, O_RDONLY));
	if (redir->type == REDIR_OUTPUT)
		return (open(filename, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE));
	return (open(filename, O_WRONLY | O_CREAT | O_APPEND, FILE_MODE));
}

void			cleanup_redirects(t_command *command)
{
	t_redirect	*redir;

	redir = command->redirects;
	while (redir && redir->next)
		redir = redir->next;
	while (redir)
	{
		if (redir->fd_file >= 0)
		{
			if (close(redir->fd_file) < 0)
				error_exit(NULL);
		}
		if (redir->fd_backup >= 0)
		{
			if (dup2(redir->fd_backup, redir->fd_io) < 0 ||
				close(redir->fd_backup) < 0)
			{
				error_exit(NULL);
			}
		}
		redir = redir->prev;
	}
}

static t_bool	check_redirect(t_redirect *redir, char *org_filename)
{
	if (redir->filename == NULL || redir->filename->next)
	{
		print_error("ambiguous redirect", org_filename);
		return (FALSE);
	}
	if ((redir->fd_file = open_file(redir)) < 0)
	{
		print_error(strerror(errno), redir->filename->data);
		return (FALSE);
	}
	return (TRUE);
}

t_bool			setup_redirects(t_command *command)
{
	t_redirect	*redir;
	char		*org_filename;

	redir = command->redirects;
	while (redir)
	{
		if ((org_filename = cs242_strdup(redir->filename->data)) == NULL)
			error_exit(NULL);
		expand_tokens(&redir->filename);
		if (check_redirect(redir, org_filename) == FALSE)
		{
			free(org_filename);
			cleanup_redirects(command);
			return (FALSE);
		}
		free(org_filename);
		redir = redir->next;
	}
	return (TRUE);
}

t_bool			dup_redirects(t_command *command, t_bool is_parent)
{
	t_redirect	*redir;

	redir = command->redirects;
	while (redir)
	{
		if (is_parent)
		{
			if ((redir->fd_backup = dup(redir->fd_io)) < 0)
			{
				print_bad_fd_error(redir->fd_io);
				return (FALSE);
			}
		}
		if (dup2(redir->fd_file, redir->fd_io) < 0)
		{
			print_bad_fd_error(redir->fd_io);
			return (FALSE);
		}
		redir = redir->next;
	}
	return (TRUE);
}
static void		exec_pipeline(t_node *nodes)
{
	extern int		g_status;
	t_command		*command;
	int				pipe[2];
	t_pipe_state	pipe_state;

	pipe_state = PIPE_WRITE_ONLY;
	while (nodes->type == NODE_PIPE)
		nodes = nodes->left;
	command = nodes->command;
	while (command)
	{
		g_status = exec_command(command, &pipe_state, pipe);
		command = command->next;
	}
	wait_commands(nodes->command);
}

static void		exec_list(t_node *nodes)
{
	extern int		g_status;
	t_pipe_state	pipe_state;

	pipe_state = NO_PIPE;
	if (!nodes)
	{
		return ;
	}
	if (nodes->type == NODE_PIPE)
	{
		exec_pipeline(nodes);
	}
	else
	{
		g_status = exec_command(nodes->command, &pipe_state, NULL);
		wait_commands(nodes->command);
	}
}

void			exec_nodes(t_node *nodes)
{
	extern t_bool g_exited;

	if (!nodes || g_exited == TRUE)
	{
		return ;
	}
	if (nodes->type == NODE_SEMICOLON)
	{
		exec_nodes(nodes->left);
		exec_nodes(nodes->right);
	}
	else
	{
		exec_list(nodes);
	}
}
void	expand_tokens(t_token **tokens)
{
	t_token	*vars[4];
	char	*expanded_str;

	if (!tokens || !*tokens)
		return ;
	vars[LAST] = NULL;
	vars[RES_LIST] = NULL;
	vars[NOW] = *tokens;
	while (vars[NOW] != NULL)
	{
		expanded_str = expand_env_var(vars[NOW]->data);
		vars[EXPANDED] = tokenise(expanded_str, TRUE);
		free(expanded_str);
		if (vars[RES_LIST] == NULL)
			vars[RES_LIST] = vars[EXPANDED];
		token_join(vars[LAST], vars[EXPANDED]);
		vars[LAST] = find_last_token(vars[RES_LIST]);
		vars[NOW] = vars[NOW]->next;
	}
	del_token_list(tokens);
	*tokens = vars[RES_LIST];
}
size_t	calc_escaped_value_len(const char *str, const char *esc)
{
	size_t index;
	size_t res;

	index = 0;
	res = 0;
	while (str[index] != 0)
	{
		if (cs242_strchr(esc, str[index]) != NULL)
			res++;
		res++;
		index++;
	}
	return (res);
}

void	copy_escaped_value(const char *src, const char *esc, char *dest)
{
	size_t res_index;
	size_t index;

	index = 0;
	res_index = 0;
	while (src[index] != 0)
	{
		if (cs242_strchr(esc, src[index]) != NULL)
		{
			dest[res_index] = '\\';
			res_index++;
		}
		dest[res_index] = src[index];
		res_index++;
		index++;
	}
	dest[res_index] = '\0';
}

char	*create_expanded_str(const char *str, t_token_state state,
	t_bool is_env)
{
	char *esc_chars;
	char *res;

	esc_chars = "\"\\$";
	if (state == STATE_GENERAL)
		esc_chars = "\'\"\\$|;><";
	if (is_env == TRUE)
		esc_chars = "\"\\$`";
	if (!(res = malloc(sizeof(char *) *
		(calc_escaped_value_len(str, esc_chars) + 1))))
		error_exit(NULL);
	copy_escaped_value(str, esc_chars, res);
	return (res);
}
static char		*setup_sign_null(int digit, int sign)
{
	char *res;

	if (!(res = malloc(sizeof(char) * digit + 1 + (sign * -1))))
		return (NULL);
	res[digit + (sign * -1)] = '\0';
	if (sign)
		res[0] = '-';
	return (res);
}
int	cs242_nbrdig(int n)
{
	int		res;
	long	tmp;

	res = 0;
	tmp = n;
	if (tmp == 0)
		return (1);
	if (tmp < 0)
		tmp *= -1;
	while (tmp > 0)
	{
		tmp = tmp / 10;
		res++;
	}
	return (res);
}
static char		*zero_itoa(void)
{
	char *res;

	if (!(res = malloc(sizeof(char) * 2)))
		return (NULL);
	res[0] = '0';
	res[1] = '\0';
	return (res);
}
char			*cs242_itoa(int n)
{
	int		digit;
	int		sign;
	int		i;
	long	tmp;
	char	*res;

	sign = 0;
	if (n == 0)
		return (zero_itoa());
	if (n < 0)
		sign = -1;
	digit = cs242_nbrdig(n);
	if (!(res = setup_sign_null(digit, sign)))
		return (NULL);
	i = digit + (sign * -1) - 1;
	tmp = n;
	if (sign)
		tmp *= -1;
	while (tmp > 0)
	{
		res[i--] = (tmp % 10) + '0';
		tmp = tmp / 10;
	}
	return (res);
}

char	*dup_env_value(char *name)
{
	char		*res;
	extern int	g_status;

	if (cs242_strcmp("?", name) == 0)
	{
		if (!(res = cs242_itoa(g_status)))
			error_exit(NULL);
	}
	else
	{
		if (!(res = cs242_strdup(get_env_data(name))))
			error_exit(NULL);
	}
	return (res);
}
void			expander_init(t_expander *exper, char *input)
{
	exper->str = cs242_strdup(input);
	if (exper->str == NULL)
		error_exit(NULL);
	exper->str_i = 0;
	exper->state = STATE_GENERAL;
}

t_token_state	judge_token_state(t_token_state state, t_token_type type)
{
	if (state == STATE_GENERAL)
	{
		if (type == CHAR_DQUOTE)
			return (STATE_IN_DQUOTE);
		if (type == CHAR_QOUTE)
			return (STATE_IN_QUOTE);
	}
	else if (state == STATE_IN_DQUOTE && type != CHAR_DQUOTE)
		return (STATE_IN_DQUOTE);
	else if (state == STATE_IN_QUOTE && type != CHAR_QOUTE)
		return (STATE_IN_QUOTE);
	return (STATE_GENERAL);
}
size_t	cs242_strlcpy(char *dst, const char *src, size_t dstsize)
{
	size_t i;

	i = 0;
	if (dstsize > 0)
	{
		while (i < dstsize - 1 && src[i])
		{
			dst[i] = src[i];
			i++;
		}
		dst[i] = '\0';
	}
	i = 0;
	while (src[i])
		i++;
	return (i);
}
int	cs242_isdigit(int c)
{
	if ('0' <= c && c <= '9')
		return (1);
	return (0);
}
char			*extract_var_name(char *str)
{
	size_t	var_len;
	char	*res;

	if (*str == '?')
		return (cs242_strdup("?"));
	var_len = 0;
	if (cs242_isdigit(*str))
	{
		if (!(res = cs242_strdup("")))
			error_exit(NULL);
		return (res);
	}
	while (cs242_isalnum(str[var_len]) || str[var_len] == '_')
		var_len++;
	if (!(res = malloc(sizeof(char) * var_len + 1)))
		error_exit(NULL);
	cs242_strlcpy(res, str, var_len + 1);
	return (res);
}

void			expand_var_in_str(t_expander *exper)
{
	char			*vars[4];
	char			*env_value;
	size_t			after_var_index;

	if (!(vars[VAR_NAME] = extract_var_name(&exper->str[exper->str_i + 1])))
		error_exit(NULL);
	if (cs242_strlen(vars[VAR_NAME]) == 0)
	{
		cs242_safe_free_char(&vars[VAR_NAME]);
		return ;
	}
	exper->str[exper->str_i] = '\0';
	env_value = dup_env_value(vars[VAR_NAME]);
	after_var_index = exper->str_i + cs242_strlen(vars[VAR_NAME]) + 1;
	if (!(vars[VALUE] = create_expanded_str(env_value, exper->state, FALSE)) ||
		!(vars[TMP] = cs242_strjoin(exper->str, vars[VALUE])) ||
		!(vars[RES] = cs242_strjoin(vars[TMP], &exper->str[after_var_index])))
		error_exit(NULL);
	exper->str_i = cs242_strlen(vars[TMP]) - 1;
	free(vars[VALUE]);
	free(vars[VAR_NAME]);
	free(vars[TMP]);
	free(env_value);
	free(exper->str);
	exper->str = vars[RES];
}

char			*expand_env_var(char *input)
{
	t_expander exper;

	if (!input)
		return (NULL);
	expander_init(&exper, input);
	while (exper.str[exper.str_i] != '\0')
	{
		exper.type = judge_token_type(exper.str[exper.str_i]);
		exper.state = judge_token_state(exper.state, exper.type);
		if (exper.type == CHAR_ESCAPE && exper.str[exper.str_i + 1] != '\0' &&
			cs242_strchr("\\\'\"$", exper.str[exper.str_i + 1]) != NULL)
		{
			exper.str_i++;
		}
		else if (exper.str[exper.str_i] == '$' &&
			(exper.state == STATE_GENERAL || exper.state == STATE_IN_DQUOTE))
		{
			expand_var_in_str(&exper);
		}
		exper.str_i++;
	}
	return (exper.str);
}
void	tokeniser_add_new_token(t_tokeniser *toker)
{
	t_token *tmp_token;

	if (toker->tok_i > 0 || (toker->is_quoted))
	{
		toker->token->data[toker->tok_i] = '\0';
		tmp_token =
			token_init(toker->str_len - toker->str_i, toker->token);
		toker->token->next = tmp_token;
		toker->token = tmp_token;
		toker->tok_i = 0;
		toker->is_quoted = FALSE;
	}
}

t_bool	is_io_number_token(t_tokeniser *toker, t_token_type type)
{
	size_t i;

	if (!toker || !toker->token || !toker->token->data ||
		toker->tok_i == 0 ||
		(type != CHAR_GREATER && type != CHAR_LESSER))
	{
		return (FALSE);
	}
	i = toker->tok_i;
	while (i != 0 && cs242_isdigit(toker->token->data[i - 1]))
	{
		i--;
	}
	if (i == 0)
	{
		return (TRUE);
	}
	return (FALSE);
}

void	general_sep_process(t_tokeniser *toker, t_token_type type, char *str)
{
	if (is_io_number_token(toker, type))
		toker->token->type = IO_NUMBER;
	tokeniser_add_new_token(toker);
	if (type != CHAR_WHITESPACE && type != CHAR_TAB)
	{
		toker->token->data[toker->tok_i++] = str[toker->str_i];
		if (str[toker->str_i + 1] == str[toker->str_i])
		{
			if (type == CHAR_GREATER)
			{
				toker->token->data[toker->tok_i++] = str[++toker->str_i];
				type = D_GREATER;
			}
			else if (type == CHAR_SEMICOLON)
			{
				toker->token->data[toker->tok_i++] = str[++toker->str_i];
				type = D_SEMICOLON;
			}
		}
		toker->token->type = type;
		tokeniser_add_new_token(toker);
	}
}

void	general_esc_process(t_tokeniser *toker, t_token_type type, char *str)
{
	if (type == CHAR_ESCAPE && str[toker->str_i + 1] != '\0')
	{
		if (toker->esc_flag)
			toker->token->data[toker->tok_i++] = str[++toker->str_i];
		else
		{
			toker->token->data[toker->tok_i++] = str[toker->str_i++];
			toker->token->data[toker->tok_i++] = str[toker->str_i];
		}
	}
	else
	{
		toker->token->data[toker->tok_i++] = str[toker->str_i];
	}
}

void	general_state(t_tokeniser *toker, t_token_type type, char *str)
{
	if (type == CHAR_QOUTE || type == CHAR_DQUOTE
	|| type == CHAR_ESCAPE || type == CHAR_GENERAL)
	{
		general_esc_process(toker, type, str);
		if (type == CHAR_QOUTE)
		{
			toker->state = STATE_IN_QUOTE;
			toker->is_quoted = TRUE;
			if (toker->esc_flag)
				toker->tok_i -= 1;
		}
		else if (type == CHAR_DQUOTE)
		{
			toker->state = STATE_IN_DQUOTE;
			toker->is_quoted = TRUE;
			if (toker->esc_flag)
				toker->tok_i -= 1;
		}
		else
			toker->state = STATE_GENERAL;
		toker->token->type = TOKEN;
	}
	else
		general_sep_process(toker, type, str);
}
static void	print_token_type(t_token_type type)
{
	if (type == CHAR_GENERAL)
		cs242_putstr_fd("GENERAL   ", STDOUT_FILENO);
	else if (type == CHAR_WHITESPACE)
		cs242_putstr_fd("WHITESPACE", STDOUT_FILENO);
	else if (type == CHAR_TAB)
		cs242_putstr_fd("TAB       ", STDOUT_FILENO);
	else if (type == CHAR_NULL)
		cs242_putstr_fd("NULL      ", STDOUT_FILENO);
	else if (type == D_SEMICOLON)
		cs242_putstr_fd(";;        ", STDOUT_FILENO);
	else if (type == D_GREATER)
		cs242_putstr_fd(">>        ", STDOUT_FILENO);
	else if (type == IO_NUMBER)
		cs242_putstr_fd("IO_NUMBER ", STDOUT_FILENO);
	else if (type == TOKEN)
		cs242_putstr_fd("TOKEN     ", STDOUT_FILENO);
	else
	{
		cs242_putchar_fd(type, STDOUT_FILENO);
		cs242_putstr_fd("         ", STDOUT_FILENO);
	}
}

void	cs242_putnbr_fd(int n, int fd)
{
	if (0 == n)
		write(fd, "0", 1);
	else if (-2147483648 == n)
		write(fd, "-2147483648", 11);
	else
	{
		if (n < 0)
		{
			n *= -1;
			write(fd, "-", 1);
		}
		if (n / 10 != 0)
		{
			cs242_putnbr_fd(n / 10, fd);
		}
		write(fd, &"0123456789"[n % 10], 1);
	}
}

void		print_token_list(t_token *tokens, t_bool esc_flag)
{
	int	index;

	index = 0;
	while (tokens)
	{
		cs242_putstr_fd("[", STDOUT_FILENO);
		cs242_putnbr_fd(index, STDOUT_FILENO);
		cs242_putstr_fd("]type: ", STDOUT_FILENO);
		print_token_type(tokens->type);
		cs242_putchar_fd('[', STDOUT_FILENO);
		cs242_putstr_fd(tokens->data, STDOUT_FILENO);
		cs242_putendl_fd("]", STDOUT_FILENO);
		tokens = tokens->next;
		index++;
	}
	if (esc_flag == TRUE)
		cs242_putendl_fd("--------------------------------", STDOUT_FILENO);
	else
		cs242_putendl_fd("================================", STDOUT_FILENO);
}

void	quote_state(t_tokeniser *toker, t_token_type type, char *str)
{
	(void)type;
	toker->token->data[toker->tok_i++] = str[toker->str_i];
	if (str[toker->str_i] == CHAR_QOUTE)
	{
		toker->state = STATE_GENERAL;
		if (toker->esc_flag == TRUE)
			toker->tok_i -= 1;
	}
}

void	d_quote_state(t_tokeniser *toker, t_token_type type, char *str)
{
	if (type == CHAR_ESCAPE && str[toker->str_i + 1] != '\0' &&
		cs242_strchr("\"\\$", str[toker->str_i + 1]) != NULL)
	{
		if (toker->esc_flag)
			toker->token->data[toker->tok_i++] = str[++toker->str_i];
		else
		{
			toker->token->data[toker->tok_i++] = str[toker->str_i++];
			toker->token->data[toker->tok_i++] = str[toker->str_i];
		}
	}
	else
	{
		toker->token->data[toker->tok_i++] = str[toker->str_i];
		if (str[toker->str_i] == CHAR_DQUOTE)
		{
			toker->state = STATE_GENERAL;
			if (toker->esc_flag == TRUE)
				toker->tok_i -= 1;
		}
	}
}
void	close_token_list(t_tokeniser *toker)
{
	if (!toker->tokens_start)
		return ;
	if (toker->state != STATE_GENERAL)
	{
		print_token_error(toker->state);
		del_token_list(&(toker->tokens_start));
		return ;
	}
	if (toker->tok_i == 0 && toker->is_quoted == FALSE)
	{
		if (toker->tokens_start == toker->token)
			del_token_list(&toker->tokens_start);
		else
			del_token(&toker->token);
	}
	else
		toker->token->data[toker->tok_i] = '\0';
}

void	tokeniser_init(t_tokeniser *toker, char *str, t_bool esc_flag)
{
	size_t	len;
	t_token	*start_token;

	len = cs242_strlen(str);
	start_token = token_init(len, NULL);
	toker->token = start_token;
	toker->tokens_start = start_token;
	toker->state = STATE_GENERAL;
	toker->str_i = 0;
	toker->tok_i = 0;
	toker->str_len = len;
	toker->esc_flag = esc_flag;
	toker->is_quoted = FALSE;
}

t_token	*tokenise(char *str, t_bool esc_flag)
{
	t_tokeniser		toker;
	t_token_type	type;

	if (!str)
		return (NULL);
	tokeniser_init(&toker, str, esc_flag);
	while (str[toker.str_i] != '\0' && toker.tokens_start)
	{
		type = judge_token_type(str[toker.str_i]);
		if (toker.state == STATE_GENERAL)
			general_state(&toker, type, str);
		else if (toker.state == STATE_IN_QUOTE)
			quote_state(&toker, type, str);
		else if (toker.state == STATE_IN_DQUOTE)
			d_quote_state(&toker, type, str);
		toker.str_i++;
	}
	close_token_list(&toker);
	if (DEBUG)
		print_token_list(toker.tokens_start, esc_flag);
	return (toker.tokens_start);
}
t_node	*add_parent_node(t_node_type type, t_node *left, t_node *right)
{
	t_node	*node;

	node = (t_node *)malloc(sizeof(t_node));
	if (!node)
		error_exit(NULL);
	node->type = type;
	node->left = left;
	node->right = right;
	node->command = NULL;
	return (node);
}

void	set_command_args(t_command *command, t_token **tokens)
{
	while (*tokens && (*tokens)->type == TOKEN)
	{
		add_copied_token(&command->args, *tokens);
		*tokens = (*tokens)->next;
	}
}

t_node	*create_command_node(t_parse_info *info)
{
	t_node	*node;

	if (!(node = (t_node *)malloc(sizeof(t_node))))
		error_exit(NULL);
	if (!(node->command = (t_command *)malloc(sizeof(t_command))))
		error_exit(NULL);
	node->type = NODE_COMMAND;
	node->left = NULL;
	node->right = NULL;
	node->command->args = NULL;
	node->command->redirects = NULL;
	node->command->pid = NO_PID;
	node->command->next = NULL;
	if (info->last_command)
		info->last_command->next = node->command;
	info->last_command = node->command;
	return (node);
}

void	del_node_list(t_node **node)
{
	if (!node || !*node)
		return ;
	if ((*node)->type == NODE_COMMAND && (*node)->command)
	{
		del_token_list(&(*node)->command->args);
		del_redirect_list(&(*node)->command->redirects);
		free((*node)->command);
	}
	del_node_list(&(*node)->left);
	del_node_list(&(*node)->right);
	free(*node);
	*node = NULL;
}
static t_token	*copy_token(t_token *token)
{
	t_token	*new;
	size_t	data_len;

	data_len = cs242_strlen(token->data);
	new = token_init(data_len, NULL);
	cs242_strlcpy(new->data, token->data, data_len + 1);
	new->type = token->type;
	return (new);
}

void			add_copied_token(t_token **list, t_token *original_token)
{
	t_token	*now;
	t_token	*copied_token;

	copied_token = copy_token(original_token);
	if (!*list)
		*list = copied_token;
	else
	{
		now = *list;
		while (now->next)
			now = now->next;
		now->next = copied_token;
		copied_token->prev = now->next;
	}
}

t_bool			has_token_type(t_token **token, t_token_type type)
{
	if ((*token)->type == type)
	{
		*token = (*token)->next;
		return (TRUE);
	}
	return (FALSE);
}

t_bool			is_redirect_token(t_token *token)
{
	return (token->type == CHAR_GREATER || token->type == CHAR_LESSER ||
		token->type == D_GREATER || token->type == IO_NUMBER);
}
t_bool			cs242_atoi_limit(const char *str, int *return_value)
{
	int				i;
	int				sign;
	unsigned long	div;
	unsigned long	res;

	i = 0;
	res = 0;
	div = INT_MAX / 10;
	while ((9 <= str[i] && str[i] <= 13) || str[i] == 32)
		i++;
	sign = str[i] == '-' ? -1 : 1;
	if (str[i] == '-' || str[i] == '+')
		i++;
	while (str[i] && ('0' <= str[i] && str[i] <= '9'))
	{
		if ((div < res || (div == res && str[i] > '7')) && sign == 1)
			return (FALSE);
		else if ((div < res || (div == res && str[i] > '8'))
		&& sign == -1)
			return (FALSE);
		res *= 10;
		res += str[i++] - '0';
	}
	*return_value = (int)res * sign;
	return (TRUE);
}
static t_bool	parse_io_redirect(t_token **tokens, t_node *command_node)
{
	t_redirect	*redirect;

	redirect = create_redirect();
	if ((*tokens)->type == IO_NUMBER)
	{
		if (cs242_atoi_limit((*tokens)->data, &redirect->fd_io) == FALSE)
			redirect->fd_io = REDIR_FD_OUT_OF_RANGE;
		*tokens = (*tokens)->next;
	}
	if (set_redirect_type(*tokens, redirect) == FALSE)
	{
		del_redirect_list(&redirect);
		return (FALSE);
	}
	*tokens = (*tokens)->next;
	if (!*tokens || (*tokens)->type != TOKEN)
	{
		del_redirect_list(&redirect);
		return (FALSE);
	}
	add_copied_token(&redirect->filename, *tokens);
	add_redirect(&command_node->command->redirects, redirect);
	*tokens = (*tokens)->next;
	return (TRUE);
}

static t_bool	parse_command(
	t_parse_info *info, t_node **node, t_token **tokens)
{
	if (!*tokens)
		return (FALSE);
	*node = create_command_node(info);
	info->last_command = (*node)->command;
	while (*tokens)
	{
		if ((*tokens)->type == TOKEN)
			set_command_args((*node)->command, tokens);
		else if (is_redirect_token(*tokens))
		{
			if (parse_io_redirect(tokens, *node) == FALSE)
			{
				del_node_list(node);
				return (FALSE);
			}
		}
		else
			break ;
	}
	if (!(*node)->command->args && !(*node)->command->redirects)
	{
		del_node_list(node);
		return (FALSE);
	}
	return (TRUE);
}

static t_bool	parse_pipeline(
	t_parse_info *info, t_node **node, t_token **tokens)
{
	t_node	*child;

	if (parse_command(info, node, tokens) == FALSE)
	{
		return (FALSE);
	}
	while (*tokens)
	{
		if (has_token_type(tokens, CHAR_PIPE))
		{
			if (parse_command(info, &child, tokens) == FALSE)
			{
				return (FALSE);
			}
			*node = add_parent_node(NODE_PIPE, *node, child);
		}
		else
		{
			break ;
		}
	}
	return (TRUE);
}

static t_bool	parse_separator(t_node **nodes, t_token **tokens)
{
	t_node			*child;
	t_parse_info	info;

	info.last_command = NULL;
	if (*tokens)
	{
		if (parse_pipeline(&info, nodes, tokens) == FALSE)
			return (FALSE);
	}
	while (*tokens)
	{
		if (has_token_type(tokens, CHAR_SEMICOLON) && *tokens)
		{
			info.last_command = NULL;
			if (parse_pipeline(&info, &child, tokens) == FALSE)
				return (FALSE);
			*nodes = add_parent_node(NODE_SEMICOLON, *nodes, child);
		}
		else
			break ;
	}
	if (*tokens)
		return (FALSE);
	return (TRUE);
}

t_bool			parse_complete_command(t_node **nodes, t_token **tokens)
{
	t_bool	result;

	*nodes = NULL;
	result = parse_separator(nodes, tokens);
	if (DEBUG)
		print_nodes(*nodes);
	return (result);
}

void	print_command_args(t_token *args, int fd)
{
	while (args)
	{
		cs242_putstr_fd(args->data, fd);
		args = args->next;
		if (args)
			cs242_putstr_fd(", ", fd);
	}
	cs242_putstr_fd("\\n", fd);
}

void	print_redirect(t_redirect *redirect, int fd)
{
	if (redirect->fd_io != REDIR_FD_NOT_SPECIFIED)
		cs242_putnbr_fd(redirect->fd_io, fd);
	if (redirect->type == REDIR_INPUT)
		cs242_putstr_fd("<", fd);
	else if (redirect->type == REDIR_OUTPUT)
		cs242_putstr_fd(">", fd);
	else if (redirect->type == REDIR_APPEND_OUTPUT)
		cs242_putstr_fd(">>", fd);
	else
		cs242_putstr_fd("?", fd);
	cs242_putstr_fd(redirect->filename->data, fd);
}

void	print_redirects(t_redirect *redirects, int fd)
{
	while (redirects)
	{
		print_redirect(redirects, fd);
		redirects = redirects->next;
		if (redirects)
			cs242_putstr_fd(", ", fd);
	}
}

void	print_node_type(t_node *node, int fd)
{
	if (node->type == NODE_SEMICOLON)
		cs242_putstr_fd("SEMICOLON", fd);
	else if (node->type == NODE_PIPE)
		cs242_putstr_fd("PIPE", fd);
	else if (node->type == NODE_COMMAND)
		cs242_putstr_fd("COMMAND", fd);
	else
		cs242_putstr_fd("unknown", fd);
}

void	print_node_label(t_node *node, int fd)
{
	cs242_putstr_fd(" [label=\"", fd);
	print_node_type(node, fd);
	cs242_putstr_fd("\\n", fd);
	if (node->type == NODE_COMMAND)
	{
		print_command_args(node->command->args, fd);
		print_redirects(node->command->redirects, fd);
	}
	cs242_putstr_fd("\"];\n", fd);
}

void	cs242_puthex_ul_fd(unsigned long n, t_bool format, int fd)
{
	if (0 == n)
		write(fd, "0", 1);
	else
	{
		if (n / 16 != 0)
		{
			cs242_puthex_ul_fd(n / 16, format, fd);
		}
		if (format == TRUE)
			write(fd, &"0123456789abcdef"[n % 16], 1);
		else
			write(fd, &"0123456789ABCDEF"[n % 16], 1);
	}
}

void	print_edge(t_node *left, t_node *right, int fd)
{
	cs242_putstr_fd(DOT_INDENT"NODE_", fd);
	cs242_puthex_ul_fd((unsigned long)left, 0, fd);
	cs242_putstr_fd(" -> NODE_", fd);
	cs242_puthex_ul_fd((unsigned long)right, 0, fd);
	cs242_putendl_fd(";", fd);
}

void	print_node(t_node *node, int fd)
{
	cs242_putstr_fd(DOT_INDENT"NODE_", fd);
	cs242_puthex_ul_fd((unsigned long)node, 0, fd);
	print_node_label(node, fd);
	if (node->left)
	{
		print_edge(node, node->left, fd);
	}
	if (node->right)
	{
		print_edge(node, node->right, fd);
	}
}

void	print_nodes_rec(t_node *node, int fd)
{
	if (!node)
		return ;
	print_node(node, fd);
	print_nodes_rec(node->left, fd);
	print_nodes_rec(node->right, fd);
}

void	print_nodes(t_node *node)
{
	int	fd;

	fd = open(DOT_FILE_NAME, O_TRUNC | O_CREAT | O_WRONLY, 0755);
	if (fd < 0)
		error_exit(NULL);
	cs242_putstr_fd("digraph AST {\n", fd);
	print_nodes_rec(node, fd);
	cs242_putstr_fd("}\n", fd);
	if (close(fd) < 0)
		error_exit(NULL);
}
void		add_redirect(t_redirect **list, t_redirect *new)
{
	t_redirect	*now;

	if (!*list)
		*list = new;
	else
	{
		now = *list;
		while (now->next)
			now = now->next;
		now->next = new;
		new->next = NULL;
		new->prev = now;
	}
}

t_redirect	*create_redirect(void)
{
	t_redirect	*redirect;

	redirect = (t_redirect *)malloc(sizeof(t_redirect));
	if (!redirect)
	{
		error_exit(NULL);
	}
	redirect->fd_io = REDIR_FD_NOT_SPECIFIED;
	redirect->fd_file = REDIR_FD_NOT_SPECIFIED;
	redirect->fd_backup = REDIR_FD_NOT_SPECIFIED;
	redirect->next = NULL;
	redirect->prev = NULL;
	redirect->filename = NULL;
	return (redirect);
}

static void	set_redirect_fd(t_redirect *redirect)
{
	if (redirect->fd_io == REDIR_FD_NOT_SPECIFIED)
	{
		if (redirect->type == REDIR_INPUT)
			redirect->fd_io = STDIN_FILENO;
		else
			redirect->fd_io = STDOUT_FILENO;
	}
}

t_bool		set_redirect_type(t_token *token, t_redirect *redirect)
{
	if (token->type == CHAR_LESSER)
	{
		redirect->type = REDIR_INPUT;
	}
	else if (token->type == CHAR_GREATER)
	{
		redirect->type = REDIR_OUTPUT;
	}
	else if (token->type == D_GREATER)
	{
		redirect->type = REDIR_APPEND_OUTPUT;
	}
	else
	{
		return (FALSE);
	}
	set_redirect_fd(redirect);
	return (TRUE);
}

void		del_redirect_list(t_redirect **redirect_p)
{
	t_redirect	*now;
	t_redirect	*tmp;

	if (!redirect_p)
		return ;
	now = *redirect_p;
	while (now)
	{
		tmp = now->next;
		del_token_list(&now->filename);
		free(now);
		now = tmp;
	}
	*redirect_p = NULL;
}

#if LEAKS

void	end(void)
{
	system("leaks minishell_leaks");
}

#endif

static t_env	*env_merge(t_env *left, t_env *right, int (*cmp)())
{
	t_env	elem;
	t_env	*next;

	next = &elem;
	while (left != NULL && right != NULL)
	{
		if (cmp(left, right) < 0)
		{
			next->next = left;
			next = next->next;
			left = left->next;
		}
		else
		{
			next->next = right;
			next = next->next;
			right = right->next;
		}
	}
	if (left == NULL)
		next->next = right;
	else
		next->next = left;
	return (elem.next);
}

static t_env	*env_mergesort_sub(t_env *lst, int (*cmp)())
{
	t_env	*left;
	t_env	*right;
	t_env	*right_head;

	if (lst == NULL || lst->next == NULL)
		return (lst);
	left = lst;
	right = lst->next;
	if (right != NULL)
		right = right->next;
	while (right != NULL)
	{
		left = left->next;
		right = right->next;
		if (right != NULL)
			right = right->next;
	}
	right_head = left->next;
	left->next = NULL;
	return (env_merge(env_mergesort_sub(lst, cmp),
		env_mergesort_sub(right_head, cmp), cmp));
}

void			env_mergesort(t_env **lst, int (*cmp)())
{
	*lst = env_mergesort_sub(*lst, cmp);
}
t_env		*get_last_env(t_env *envs)
{
	t_env	*target;

	if (!envs)
		return (NULL);
	target = envs;
	while (target->next)
		target = target->next;
	return (target);
}

size_t		get_environ_size(t_env *envs)
{
	size_t	size;

	size = 0;
	while (envs)
	{
		if (can_generate_environ(envs))
			size++;
		envs = envs->next;
	}
	return (size);
}

t_env		*get_env(const char *name)
{
	t_env			*now;
	extern t_env	*g_envs;

	if (!g_envs || !name)
		return (NULL);
	now = g_envs;
	while (now)
	{
		if (cs242_strcmp(now->name, (char *)name) == 0)
			return (now);
		now = now->next;
	}
	return (NULL);
}

const char	*get_env_data(char *name)
{
	t_env			*now;
	extern t_env	*g_envs;

	if (!g_envs || !name)
		return (NULL);
	now = g_envs;
	while (now)
	{
		if (cs242_strcmp(now->name, name) == 0)
		{
			if (!now->value)
				return ("");
			else
				return (now->value);
		}
		now = now->next;
	}
	return ("");
}
char	*cs242_substr(char const *s, unsigned int start, size_t len)
{
	char			*res;
	size_t			char_count;
	size_t			i;

	if (!s)
		return (NULL);
	if (len == 0 || start > cs242_strlen(s))
	{
		if (!(res = malloc(sizeof(char))))
			return (NULL);
		*res = '\0';
		return (res);
	}
	char_count = cs242_strlen(&s[start]) > len ? len : cs242_strlen(&s[start]);
	if (!(res = malloc(sizeof(char) * (char_count + 1))))
		return (NULL);
	i = 0;
	while (i < len && s[start + i])
	{
		res[i] = s[start + i];
		i++;
	}
	res[i] = '\0';
	return (res);
}
t_env		*create_new_env(char *env_str)
{
	t_env	*env;
	char	*sep;

	if (!(env = malloc(sizeof(t_env))))
		error_exit(NULL);
	sep = cs242_strchr(env_str, '=');
	if (!sep)
	{
		if (!(env->name = cs242_strdup(env_str)))
			error_exit(NULL);
		env->value = NULL;
	}
	else
	{
		if (!(env->name = cs242_substr(env_str, 0, sep - env_str)) ||
			!(env->value = cs242_strdup(sep + 1)))
			error_exit(NULL);
	}
	env->is_env = TRUE;
	env->next = NULL;
	return (env);
}

void		free_env(t_env *env)
{
	free(env->name);
	free(env->value);
	env->name = NULL;
	env->value = NULL;
	free(env);
}

static void	set_env_value(t_env *env, const char *new_value, t_bool append_flag)
{
	char	*old_value;

	old_value = env->value;
	if (append_flag == TRUE)
	{
		if (old_value || new_value)
		{
			if (!(env->value = cs242_strjoin(old_value, new_value)))
				error_exit(NULL);
		}
		else
			env->value = NULL;
	}
	else
	{
		if (new_value)
		{
			if (!(env->value = cs242_strdup(new_value)))
				error_exit(NULL);
		}
		else
			env->value = NULL;
	}
	cs242_safe_free_char(&old_value);
}

void		update_env_value(const char *env_name, const char *new_value,
	t_bool is_env_var, t_bool append_flag)
{
	extern t_env	*g_envs;
	t_env			*env;

	if (!env_name)
		return ;
	if (!(env = get_env(env_name)))
	{
		env = create_new_env((char *)env_name);
		env->is_env = is_env_var;
		add_env(&g_envs, env);
	}
	else
	{
		if (env->is_env == FALSE)
			env->is_env = is_env_var;
		if (!new_value)
			return ;
	}
	set_env_value(env, new_value, append_flag);
}

t_env		*copy_envs(t_env *envs)
{
	t_env	*res;
	t_env	*now_env;
	t_env	*copy_env;

	now_env = envs;
	res = NULL;
	while (now_env)
	{
		if ((copy_env = (t_env *)malloc(sizeof(t_env))) == NULL)
			error_exit(NULL);
		copy_env->name = now_env->name;
		copy_env->value = now_env->value;
		copy_env->is_env = now_env->is_env;
		copy_env->next = NULL;
		add_env(&res, copy_env);
		now_env = now_env->next;
	}
	return (res);
}
t_env	*create_envs_from_environ(void)
{
	extern char	**environ;
	size_t		i;
	t_env		*envs;
	t_env		*now_env;

	envs = NULL;
	i = 0;
	while (environ[i])
	{
		now_env = create_new_env(environ[i]);
		add_env(&envs, now_env);
		i++;
	}
	return (envs);
}

char	**generate_environ(t_env *envs)
{
	char	**environ;
	char	*tmp;
	size_t	env_size;
	size_t	i;

	env_size = get_environ_size(envs);
	if (!(environ = (char **)malloc(sizeof(char *) * (env_size + 1))))
		error_exit(NULL);
	i = 0;
	while (i < env_size)
	{
		if (can_generate_environ(envs))
		{
			if (!(environ[i] = cs242_strjoin(envs->name, "=")))
				error_exit(NULL);
			tmp = environ[i];
			if (!(environ[i] = cs242_strjoin(environ[i], envs->value)))
				error_exit(NULL);
			free(tmp);
			i++;
		}
		envs = envs->next;
	}
	environ[i] = NULL;
	return (environ);
}

t_bool	can_generate_environ(t_env *env)
{
	if (env->value == NULL)
		return (FALSE);
	if (env->is_env == FALSE)
		return (FALSE);
	return (TRUE);
}

void	add_env(t_env **envs, t_env *new_env)
{
	if (!new_env || !envs)
		return ;
	if (!*envs)
		*envs = new_env;
	else
	{
		get_last_env(*envs)->next = new_env;
		new_env->next = NULL;
	}
}

void	del_env(t_env **envs, char *name)
{
	t_env	*now;
	t_env	*prev;

	prev = NULL;
	now = *envs;
	while (now)
	{
		if (cs242_strncmp(now->name, name, cs242_strlen(name) + 1) == 0)
		{
			if (prev)
				prev->next = now->next;
			else
				*envs = now->next;
			cs242_safe_free_char(&now->name);
			cs242_safe_free_char(&now->value);
			free(now);
			now = NULL;
			break ;
		}
		prev = now;
		now = now->next;
	}
}
void	print_syntax_error(t_token *token)
{
	extern int	g_status;

	cs242_putstr_fd(
		"minishell: syntax error near unexpected token `", STDERR_FILENO);
	if (token)
	{
		cs242_putstr_fd(token->data, STDERR_FILENO);
	}
	else
	{
		cs242_putstr_fd("newline", STDERR_FILENO);
	}
	cs242_putendl_fd("'", STDERR_FILENO);
	g_status = STATUS_SYNTAX_ERROR;
}

void	print_token_error(t_token_state state)
{
	extern int	g_status;

	if (state == STATE_IN_DQUOTE)
		print_error("unexpected EOF while looking for matching `\"'", NULL);
	if (state == STATE_IN_QUOTE)
		print_error("unexpected EOF while looking for matching `''", NULL);
	g_status = STATUS_TOKEN_ERROR;
}

void	print_bad_fd_error(int fd)
{
	char	*fd_str;

	if (fd < 0)
	{
		print_error(strerror(errno), "file descriptor out of range");
	}
	else
	{
		if (!(fd_str = cs242_itoa(fd)))
			error_exit(NULL);
		print_error(strerror(errno), fd_str);
		free(fd_str);
	}
}

void	print_numeric_argument_error(char *arg)
{
	cs242_putstr_fd("minishell: exit: ", STDERR_FILENO);
	cs242_putstr_fd(arg, STDERR_FILENO);
	cs242_putendl_fd(": numeric argument required", STDERR_FILENO);
}

void	print_identifier_error(char *command, char *name)
{
	cs242_putstr_fd("minishell: ", STDERR_FILENO);
	cs242_putstr_fd(command, STDERR_FILENO);
	cs242_putstr_fd(": `", STDERR_FILENO);
	cs242_putstr_fd(name, STDERR_FILENO);
	cs242_putendl_fd("': not a valid identifier", STDERR_FILENO);
}
void	print_error(char *message, char *command)
{
	cs242_putstr_fd("minishell: ", STDERR_FILENO);
	if (command)
	{
		cs242_putstr_fd(command, STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
	}
	cs242_putendl_fd(message, STDERR_FILENO);
}

void	error_exit(char *command)
{
	print_error(strerror(errno), command);
	exit(EXIT_FAILURE);
}

void	print_error_filename(char *message, char *command, char *file)
{
	cs242_putstr_fd("minishell: ", STDERR_FILENO);
	if (command)
	{
		cs242_putstr_fd(command, STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
	}
	if (file)
	{
		cs242_putstr_fd(file, STDERR_FILENO);
		cs242_putstr_fd(": ", STDERR_FILENO);
	}
	cs242_putendl_fd(message, STDERR_FILENO);
}

char	*cs242_strrchr(const char *s, int c)
{
	int i;

	i = 0;
	while (s[i])
		i++;
	while (s[i] != (char)c)
	{
		if (i == 0)
			return (NULL);
		i--;
	}
	return ((char *)&s[i]);
}
char	*cs242_strcpy_forward(char *dest, char *src)
{
	size_t index;

	index = 0;
	while (src[index])
	{
		dest[index] = src[index];
		index++;
	}
	dest[index] = '\0';
	return (&(dest[index]));
}
char	*cpy_path_elem(char *path_p, char *elem, char *start)
{
	if (cs242_strcmp(elem, "..") == 0)
	{
		path_p = cs242_strrchr(start, '/');
		if (!path_p)
			path_p = start;
		*path_p = '\0';
	}
	else if (cs242_strcmp(elem, ".") != 0)
	{
		path_p = cs242_strcpy_forward(path_p, "/");
		path_p = cs242_strcpy_forward(path_p, elem);
	}
	return (path_p);
}

t_bool	cpy_canonical_path(char **split, char **res)
{
	char	*start;
	char	*path_p;
	size_t	index;

	start = *res;
	*start = '\0';
	index = 0;
	path_p = start;
	while (split[index])
	{
		path_p = cpy_path_elem(path_p, split[index], start);
		if (path_p == start)
			path_p = cs242_strcpy_forward(path_p, "/");
		if (!is_directory(start))
			return (FALSE);
		index++;
	}
	if (path_p == start)
		path_p = cs242_strcpy_forward(path_p, "/");
	return (TRUE);
}

void	add_slash_path_front(char *path, char **res)
{
	char *added_res;

	if (!path || !res || !*res)
		return ;
	if (cs242_strncmp(path, "//", 2) == 0 && path[2] != '/' &&
		cs242_strncmp(*res, "//", 2) != 0)
	{
		if (!(added_res = cs242_strjoin("/", *res)))
			error_exit(NULL);
		cs242_safe_free_char(res);
		*res = added_res;
	}
}
static void		remove_c(char *src, char c, size_t len)
{
	size_t i;

	i = 0;
	while (i < len)
	{
		if (src[i] == c)
			src[i] = '\0';
		i++;
	}
}
static size_t	count_separated(char *src, size_t len)
{
	size_t i;
	size_t res;

	i = 0;
	res = 0;
	while (i < len)
	{
		if (src[i] != '\0')
		{
			i += cs242_strlen(&src[i]);
			res++;
		}
		i++;
	}
	return (res);
}
static t_bool	set_separated(char *src, size_t len, char **result)
{
	size_t i;
	size_t parent_count;

	i = 0;
	parent_count = 0;
	while (i < len)
	{
		if (src[i] != '\0')
		{
			if (!(result[parent_count] = cs242_strdup(&src[i])))
			{
				while (parent_count > 0)
					free(result[--parent_count]);
				return (FALSE);
			}
			i += cs242_strlen(&src[i]);
			parent_count++;
		}
		i++;
	}
	return (TRUE);
}
char			**cs242_split(char const *s, char c)
{
	char	*src;
	size_t	len;
	size_t	sep_count;
	char	**res;

	if (!s)
		return (NULL);
	len = cs242_strlen(s);
	if (!(src = cs242_strdup(s)))
		return (NULL);
	sep_count = 0;
	remove_c(src, c, len);
	sep_count = count_separated(src, len);
	if (!(res = malloc(sizeof(char *) * (sep_count + 1))))
		return (NULL);
	res[sep_count] = NULL;
	if (!set_separated(src, len, res))
	{
		free(res);
		res = NULL;
	}
	free(src);
	return (res);
}
char	*path_canonicalisation(char *path)
{
	char			**split;
	char			*res;

	if (!path)
		return (NULL);
	if (!(split = cs242_split(path, '/')) ||
		!(res = malloc(sizeof(char *) * (cs242_strlen(path) + 1))))
		error_exit(NULL);
	if (!(cpy_canonical_path(split, &res)))
		cs242_safe_free_char(&res);
	cs242_safe_free_split(&split);
	add_slash_path_front(path, &res);
	return (res);
}
char	*join_path(const char *prev, const char *next)
{
	char	*tmp;
	char	*res;
	size_t	index;

	if (!prev || !next)
		return (NULL);
	tmp = NULL;
	res = NULL;
	if (!(tmp = cs242_strjoin(prev, "/")))
		error_exit(NULL);
	index = cs242_strlen(tmp);
	if (index >= 2 && tmp[index - 2] == '/')
		tmp[index - 1] = '\0';
	if (!(res = cs242_strjoin(tmp, next)))
		error_exit(NULL);
	free(tmp);
	return (res);
}

t_bool	is_directory(const char *path)
{
	t_stat path_stat;

	if (stat(path, &path_stat) == -1)
		return (FALSE);
	if (S_ISDIR(path_stat.st_mode))
		return (TRUE);
	return (FALSE);
}

char	**allocate_colon_unit_parent(const char *str)
{
	size_t	index;
	size_t	colon_count;
	char	**res;

	index = 0;
	colon_count = 0;
	while (str[index])
	{
		if (str[index] == ':')
			colon_count++;
		index++;
	}
	if (!(res = malloc(sizeof(char *) * (colon_count + 2))))
		error_exit(NULL);
	res[colon_count + 1] = NULL;
	return (res);
}

char	*strdup_colon_unit(char *unit, const char *default_value)
{
	char *res;

	if (!unit)
		return (NULL);
	if (cs242_strlen(unit) == 0)
	{
		if (!(res = cs242_strdup(default_value)))
			error_exit(NULL);
	}
	else
	{
		if (!(res = cs242_strdup(unit)))
			error_exit(NULL);
	}
	return (res);
}

char	**get_colon_units(const char *str, const char *default_value)
{
	char	**res;
	size_t	index;
	char	*copied_str;
	char	*unit_start;
	char	*unit_end;

	index = 0;
	res = allocate_colon_unit_parent(str);
	if (!(copied_str = cs242_strdup(str)))
		error_exit(NULL);
	unit_start = copied_str;
	unit_end = cs242_strchr(unit_start, ':');
	while (unit_end)
	{
		*unit_end = '\0';
		res[index] = strdup_colon_unit(unit_start, default_value);
		unit_start = unit_end + 1;
		unit_end = cs242_strchr(unit_start, ':');
		index++;
	}
	res[index] = strdup_colon_unit(unit_start, default_value);
	cs242_safe_free_char(&copied_str);
	return (res);
}
t_bool	is_same_dir(const char *dir_1, const char *dir_2)
{
	t_stat stat1;
	t_stat stat2;

	if (!dir_1 || !dir_2)
		return (FALSE);
	if (stat(dir_1, &stat1) < 0 ||
		stat(dir_2, &stat2) < 0)
	{
		return (FALSE);
	}
	if (stat1.st_ino == stat2.st_ino)
		return (TRUE);
	return (FALSE);
}

void	old_pwd_init(void)
{
	t_env			*old_pwd_env;
	extern t_env	*g_envs;

	old_pwd_env = get_env("OLDPWD");
	if (!old_pwd_env)
	{
		if (!(old_pwd_env = malloc(sizeof(t_env))) ||
			!(old_pwd_env->name = cs242_strdup("OLDPWD")))
		{
			error_exit(NULL);
		}
		old_pwd_env->value = NULL;
		old_pwd_env->next = NULL;
		old_pwd_env->is_env = TRUE;
		add_env(&g_envs, old_pwd_env);
	}
	cs242_safe_free_char(&(old_pwd_env->value));
}

void	pwd_value_init(t_env *pwd_env)
{
	char			*cwd;
	extern char		*g_pwd;

	if (!(cwd = getcwd(NULL, 0)))
		error_exit(NULL);
	if (!pwd_env->value || !is_same_dir(pwd_env->value, cwd))
	{
		if (!(pwd_env->value = cs242_strdup(cwd)))
			error_exit(NULL);
	}
	if (!(g_pwd = cs242_strdup(pwd_env->value)))
		error_exit(NULL);
	free(cwd);
}

void	pwd_init(void)
{
	t_env			*pwd_env;
	extern t_env	*g_envs;
	extern char		*g_pwd;

	pwd_env = get_env("PWD");
	if (!pwd_env)
	{
		if (!(pwd_env = malloc(sizeof(t_env))) ||
			!(pwd_env->name = cs242_strdup("PWD")))
		{
			error_exit(NULL);
		}
		pwd_env->value = NULL;
		pwd_env->next = NULL;
		pwd_env->is_env = TRUE;
		add_env(&g_envs, pwd_env);
	}
	pwd_value_init(pwd_env);
}

void	minishell_init(void)
{
	extern t_env *g_envs;

	g_envs = create_envs_from_environ();
	pwd_init();
	shlvl_init();
	old_pwd_init();
}
int	cs242_isspace(int c)
{
	if ((9 <= c && c <= 13) || c == 32)
		return (1);
	return (0);
}
t_bool	is_digit_str(char *str)
{
	size_t	index;
	t_bool	has_digit;

	index = 0;
	has_digit = FALSE;
	while (cs242_isspace(str[index]))
		index++;
	if (str[index] == '+' || str[index] == '-')
		index++;
	while (str[index])
	{
		if (cs242_isdigit(str[index]))
			has_digit = TRUE;
		else
			break ;
		index++;
	}
	while (str[index] == ' ' || str[index] == '\t')
		index++;
	if (str[index] == '\0' && has_digit == TRUE)
		return (TRUE);
	else
		return (FALSE);
}

void	put_shlvl_warning(int num)
{
	char	*str_num;
	char	*tmp;
	char	*msg;

	str_num = NULL;
	tmp = NULL;
	msg = NULL;
	if (!(str_num = cs242_itoa(num)) ||
		!(tmp = cs242_strjoin("shell level (", str_num)) ||
		!(msg = cs242_strjoin(tmp, ") too high, resetting to 1")))
	{
		error_exit(NULL);
	}
	print_error(msg, "warning");
	free(str_num);
	free(tmp);
	free(msg);
}
int				cs242_atoi_overflow_zero(const char *str)
{
	int				i;
	int				sign;
	unsigned long	ov_div;
	unsigned long	result;

	i = 0;
	result = 0;
	ov_div = MY_LONG_MAX / 10;
	while ((9 <= str[i] && str[i] <= 13) || str[i] == 32)
		i++;
	sign = str[i] == '-' ? -1 : 1;
	if (str[i] == '-' || str[i] == '+')
		i++;
	while (str[i] && ('0' <= str[i] && str[i] <= '9'))
	{
		if ((ov_div < result || (ov_div == result && str[i] > '7'))
		&& sign == 1)
			return (0);
		else if ((ov_div < result || (ov_div == result && str[i] > '8'))
		&& sign == -1)
			return (0);
		result *= 10;
		result += str[i++] - '0';
	}
	return ((int)result * sign);
}

void	calc_shlvl(char **shlvl)
{
	char	*res;
	int		num;

	num = cs242_atoi_overflow_zero(*shlvl);
	if (!is_digit_str(*shlvl))
		num = 0;
	num++;
	if (num == 1000)
		res = cs242_strdup("");
	else if (num < 1)
		res = cs242_strdup("0");
	else if (0 < num && num < 1000)
		res = cs242_itoa(num);
	else
	{
		put_shlvl_warning(num);
		res = cs242_strdup("1");
	}
	cs242_safe_free_char(shlvl);
	*shlvl = res;
}

void	shlvl_init(void)
{
	t_env			*shlvl_env;
	extern t_env	*g_envs;

	shlvl_env = get_env("SHLVL");
	if (!shlvl_env)
	{
		if (!(shlvl_env = malloc(sizeof(t_env))) ||
			!(shlvl_env->name = cs242_strdup("SHLVL")) ||
			!(shlvl_env->value = cs242_strdup("1")))
		{
			error_exit(NULL);
		}
		shlvl_env->next = NULL;
		shlvl_env->is_env = TRUE;
		add_env(&g_envs, shlvl_env);
		return ;
	}
	else
	{
		calc_shlvl(&(shlvl_env->value));
		if (!(shlvl_env->value))
			error_exit(NULL);
	}
}
void		handle_signal(int signal)
{
	extern int		g_status;
	extern t_bool	g_interrupted;
	int				prev_errno;

	prev_errno = errno;
	cs242_putstr_fd(BACK_CURSOR, STDERR_FILENO);
	cs242_putstr_fd(CLEAR_FROM_CURSOR, STDERR_FILENO);
	if (signal == SIGINT)
	{
		cs242_putstr_fd("\n"SHELL_PROMPT, STDERR_FILENO);
		g_status = 1;
		g_interrupted = TRUE;
	}
	errno = prev_errno;
}

void		set_signal_handler(void (*func)(int))
{
	if (signal(SIGINT, func) == SIG_ERR)
	{
		error_exit(NULL);
	}
	if (signal(SIGQUIT, func) == SIG_ERR)
	{
		error_exit(NULL);
	}
}
t_token	*find_last_token(t_token *tokens)
{
	t_token *now;

	if (!tokens)
		return (NULL);
	now = tokens;
	while (now->next != NULL)
	{
		now = now->next;
	}
	return (now);
}

size_t	calc_tokens_len(t_token *tokens)
{
	t_token	*now;
	size_t	res;

	res = 0;
	if (!tokens)
		return (res);
	now = tokens;
	while (now != NULL)
	{
		res++;
		now = now->next;
	}
	return (res);
}

void	token_join(t_token *prev_token, t_token *next_token)
{
	if (!prev_token || !next_token ||
		prev_token == next_token)
		return ;
	prev_token->next = next_token;
	next_token->prev = prev_token;
}
void			del_token(t_token **token_p)
{
	t_token *token;

	if (!token_p || !*token_p)
		return ;
	token = *token_p;
	if (token->data)
		free(token->data);
	if (token->next)
		token->next->prev = token->prev;
	if (token->prev)
		token->prev->next = token->next;
	free(token);
	*token_p = NULL;
}

void			del_token_list(t_token **token_p)
{
	t_token *now;
	t_token *tmp;

	if (!token_p || !*token_p)
		return ;
	now = *token_p;
	while (now)
	{
		tmp = now->next;
		del_token(&now);
		now = tmp;
	}
	*token_p = NULL;
}

t_token_type	judge_token_type(char c)
{
	int			command_count;
	const char	commands[] = {
		'|', '\'', '\"', ' ', ';', '\\', '>', '<', '\t', '\0'};

	command_count = 10;
	while (command_count--)
	{
		if (commands[command_count] == c)
			return (commands[command_count]);
	}
	return (CHAR_GENERAL);
}

t_token			*token_init(size_t len, t_token *prev)
{
	t_token *res;

	if (!(res = malloc(sizeof(t_token))))
		error_exit(NULL);
	if (!(res->data = malloc(sizeof(char) * (len + 1))))
		error_exit(NULL);
	res->data[0] = '\0';
	res->type = TOKEN;
	res->next = NULL;
	res->prev = prev;
	return (res);
}

t_env	*g_envs;
int		g_status;
char	*g_pwd;
t_bool	g_interactive;
t_bool	g_interrupted;
t_bool	g_exited;

void	run_commandline(char *line)
{
	char *inputString = line;
	FILE *q = fopen("/tmp/history.txt", "a+");
	fprintf(q, "%s\n", inputString);
	fclose(q);

    if(strcmp(inputString, "history")==0)
	{
		strcpy(inputString, "cat /tmp/history.txt");
	}

	t_token	*tokens;
	t_token	*start_token;
	t_node	*nodes;

	tokens = tokenise(line, FALSE);
	start_token = tokens;
	if (parse_complete_command(&nodes, &tokens) == FALSE)
		print_syntax_error(tokens);
	else
		exec_nodes(nodes);	
	del_token_list(&start_token);
	del_node_list(&nodes);
	
}

void	handle_eof(char *line, char *buf_line)
{
	if (line[0] == '\0' && (buf_line == NULL || g_interrupted == TRUE))
	{
		cs242_putendl_fd("exit", STDERR_FILENO);
		exit(g_status);
	}
	cs242_putstr_fd(CLEAR_FROM_CURSOR, STDERR_FILENO);
}

void	process_input(int *gnl_result, char **buf_line)
{
	char	*line;
	char	*tmp;

	if ((*gnl_result = cs242_get_next_line(STDIN_FILENO, &line)) < 0)
		error_exit(NULL);
	if (*gnl_result == 0)
		handle_eof(line, *buf_line);
	if (g_interrupted == TRUE)
		cs242_safe_free_char(buf_line);
	tmp = *buf_line;
	if ((*buf_line = cs242_strjoin(*buf_line, line)) == NULL)
		error_exit(NULL);
	free(tmp);
	if (*gnl_result)
	{
		run_commandline(*buf_line);
		cs242_safe_free_char(buf_line);
	}
	free(line);
}

void	loop_shell(void)
{
	int		gnl_result;
	char	*buf_line;

	gnl_result = 1;
	buf_line = NULL;
	while (TRUE)
	{
		g_interrupted = FALSE;
		g_exited = FALSE;
		set_signal_handler(handle_signal);
		if (gnl_result)
			cs242_putstr_fd(SHELL_PROMPT, STDERR_FILENO);
		process_input(&gnl_result, &buf_line);
	}
}

int		main(int argc, char *argv[])
{

	minishell_init();                            // This function initialises the minishell

	if (argc > 2 && cs242_strcmp("-c", argv[1]) == 0)
	{
		g_interactive = FALSE;
		run_commandline(argv[2]);
	}
	else
	{
		g_interactive = TRUE;
		loop_shell();
	}
	return (g_status);
}