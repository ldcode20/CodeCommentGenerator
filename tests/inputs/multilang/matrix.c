#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int rows;
    int cols;
    double *data;
} Matrix;

static int count_nonzero(const Matrix *m);

Matrix *matrix_create(int rows, int cols)
{
	Matrix *m = malloc(sizeof(Matrix));
	if (m == NULL) {
		return NULL;
	}
	m->rows = rows;
	m->cols = cols;
	m->data = calloc((size_t)rows * cols, sizeof(double));
	return m;
}

// Frees the matrix and its data buffer.
void matrix_free(Matrix *m)
{
	free(m->data);
	free(m);
}

double matrix_trace(const Matrix *m)
{
	double total = 0.0;
	for (int i = 0; i < m->rows && i < m->cols; i++) {
		total += m->data[i * m->cols + i];
	}
	return total;
}

static int count_nonzero(const Matrix *m)
{
	int count = 0;
	for (int i = 0; i < m->rows; i++) {
		for (int j = 0; j < m->cols; j++) {
			switch (m->data[i * m->cols + j] != 0.0) {
			case 1:
				count++;
				break;
			default:
				break;
			}
		}
	}
	return count;
}

int main(void)
{
	Matrix *m = matrix_create(3, 3);
	printf("trace=%f nonzero=%d\n", matrix_trace(m), count_nonzero(m));
	matrix_free(m);
	return 0;
}
