#include <stdio.h>

void swap(long *a, long *b) {
    long temp = *a;
    *a = *b;
    *b = temp;
}

int partition(long arr[], int low, int high) {
    long pivot = arr[high];
    int i = low - 1;
  
    for (int j = low; j <= high - 1; j++) {
        if (arr[j] < pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
  
    swap(&arr[i + 1], &arr[high]);
    return (i + 1);
}

void quickSort(long arr[], int low, int high) {
    if (low < high) {
        int pivot = partition(arr, low, high);
        quickSort(arr, low, pivot - 1);
        quickSort(arr, pivot + 1, high);
    }
}

void sort_func(long *numbers, int n) {
    quickSort(numbers, 0, n - 1);
}

int main() {
    long *numbers;
    int n;

    sort_func(numbers, n);

    // printf("Sorted array: ");
    // for (int i = 0; i < n; i++) {
    //     printf("%ld ", numbers[i]);
    // }
    // printf("\n");
    return 0;
}