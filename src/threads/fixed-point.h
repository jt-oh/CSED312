#define F 1<<14

#define CONVERT_TO_FP(n) ((n) * (F))
#define CONVERT_TO_INT(x) (((x) > 0) ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
#define ROUND_DOWN_TO_INT(x) ((x) / (F))
#define ADD_FP_FP(x, y) ((x) + (y))
#define SUB_FP_FP(x, y) ((x) - (y))
#define ADD_FP_INT(x, n) ((x) + (n) * (F))
#define SUB_FP_INT(x, n) ((x) - (n) * (F))
#define MUL_FP_FP(x, y) (((int64_t)(x) * (y)) / (F))
#define MUL_FP_INT(x, n) ((x) * (n))
#define DIV_FP_FP(x, y) (((int64_t)(x) * (F)) / (y))
#define DIV_FP_INT(x, n) ((x) / (n))
