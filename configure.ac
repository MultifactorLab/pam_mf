AC_INIT([pam_mf], [1.0.0])
AC_PROG_CC
AC_CANONICAL_HOST
case "$host" in
     *darwin*)         PAM_DIR="/usr/lib/pam" ;;
     *freebsd*)        PAM_DIR="/usr/lib" ;;
     *linux*)          PAM_DIR="/lib/security" ;;
     *)                PAM_DIR="/usr/lib/security" ;; # NetBSD, Solaris, AIX, HP-UX
esac
AC_ARG_WITH(pamdir,
  AS_HELP_STRING([--with-pamdir=DIR],[override the default install DIR]),
  [ pamdir=${withval} ],
  [ pamdir=${PAM_DIR} ]
)
AC_SUBST(PAMDIR, "$pamdir")
AC_CONFIG_FILES([Makefile])
AC_OUTPUT