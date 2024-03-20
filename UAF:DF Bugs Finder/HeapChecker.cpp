#include <iostream>
#include <vector>
#include <cstdlib>

using namespace std;
struct Interval {
    char* start;
    char* end;
};

vector<Interval> intervals;

extern "C" void* mymalloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr != NULL) {
        char* start = static_cast<char*>(ptr);
        char* end = start + size;
        intervals.push_back({start, end});
    }
    return ptr;
}

extern "C" void* mycalloc(size_t num, size_t size) {
    void* ptr = calloc(num, size);
    if (ptr != NULL) {
        char* start = static_cast<char*>(ptr);
        char* end = start + num * size;
        intervals.push_back({start, end});
    }
    return ptr;
}

extern "C" void myfree(void* ptr, int line) {
    char* target = static_cast<char*>(ptr);
    bool found = false;

    for (auto i = intervals.begin(); i != intervals.end(); ) {
        if (target == i->start) {
            i = intervals.erase(i); // Remove the interval and update 
iterator
            found = true;
            break;
        } else {
            ++i;
        }
    }

    if (!found) {
        cout << "Double free bug at line: " << line << "\n";
        exit(1);
    } else {
        free(ptr); // Perform the actual free operation if the pointer was 
valid
    }
}

extern "C" void validatePointer(void* ptr, int line) {
    //after optimization, ptr here is (1) returned from the malloc() or 
calloc() functions 
    // OR (2) passed as an argument into the free() function
    // no need to check if ptr is pointing to an address in stack

    char* target = static_cast<char*>(ptr);
    bool isValid = false;

    for (const auto& i : intervals) {
        if (target >= i.start && target < i.end) {
            isValid = true;
            break; // Pointer is within a valid interval
        }
    }

    if (!isValid) {
        cout << "Use after free bug at line: " << line << "\n";
        exit(1);
    }
}
