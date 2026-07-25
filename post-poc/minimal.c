/* minimal test */
#include <windows.h>
#include <stdio.h>
int main(void) {
    FILE *f = fopen("minimal_test.txt", "w");
    fprintf(f, "hello world\n");
    fclose(f);
    return 0;
}
