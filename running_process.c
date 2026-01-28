
#include <stdio.h>
#include <string.h>

void notifier()
{
    printf("Notifier called!\n");
}

int main()
{
    char input[256];
    while (1) {
        printf("Type 'r' to read doc.txt, 'q' to quit: ");
        if (!fgets(input, sizeof(input), stdin)) break;
        // Remove trailing newline
        input[strcspn(input, "\n")] = 0;
        if (input[0] == 'q') {
            break;
        } else if (input[0] == 'r') {
            FILE* f = fopen("doc.txt", "r");
            if (!f) {
                printf("Failed to open doc.txt\n");
                continue;
            }
            printf("-------doc.txt-----\n");
            char file_line[1024];
            while (fgets(file_line, sizeof(file_line), f)) {
                printf("%s\n", file_line);
            }
            fclose(f);
        }
    }
    return 0;
}