Hide
Type "${AUTHD_TEST_TAPE_COMMAND}"
Enter
Sleep ${AUTHD_SLEEP_COMMAND}
Show

Hide
Type "user-integration-max-attempts"
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Enter
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "2"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT}
Show

Hide
Type "wrongpass"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT} * 2
Show

Hide
Type "wrongpass"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT} * 2
Show

Hide
Type "wrongpass"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT} * 2
Show

Hide
Type "wrongpass"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT} * 2
Show

Hide
Type "wrongpass"
Enter
Sleep ${AUTHD_SLEEP_DEFAULT} * 2
Show

Sleep ${AUTHD_SLEEP_DEFAULT}
