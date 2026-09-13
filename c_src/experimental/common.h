#ifndef NUK4SD_EXPERIMENTAL_COMMON_H
#define NUK4SD_EXPERIMENTAL_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Mini-Init PID 1 Supervisor (--init)
 * Executa o loop de colheita de processos órfãos (waitpid) e repasse de sinais.
 */
int nuk_mini_init(const char *exec_path, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* NUK4SD_EXPERIMENTAL_COMMON_H */
