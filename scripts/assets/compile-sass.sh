#!/bin/sh
#
# Compile sass files.
#
# Run this from the root of edx-platform, after ... TOOD
# but before ... TODO

# Enable stricter sh behavior.
set -eu  

USAGE="\
USAGE:\n\
    $0 [OPTIONS] lms [<THEME_DIR>]\n\
    $0 [OPTIONS] cms [<THEME_DIR>]\n\
\n\
OPTIONS:\n\
    -n, --node-modules <NODE_MODULES_PATH>   Path to installed node_modules directory.\n\
                                             Defaults to ./node_modules.\n\
    -w, --watch                              Watch sass directories and compile and recompile whenever changed\n\
    -f, --force                              Remove existing css before generating new css\n\
    -d, --dev                                Dev mode: whether to show source comments in resulting css\n\
        --dry                                Dry run: don't do anything; just print what _would_ be done.\n\
    -h, --help                               Display this.\n\
"

# Commands we use.
# In --dry mode, these are overriden to 'echo <command>'
rm='rm'
sassc='sassc'
rtlcss='rtlcss'

# By default, we look for node_modules in the current directory.
# Some Open edX distributions may want node_modules to be located somewhere
# else, so we let this be configured with -n|--node-modules.
node_modules_path="./node_modules"

# system can be: lms or cms
# theme_dir can be: a path, or empty
system=""
theme_dir=""

# Flags.
#  Empty string    (-z) => false
#  Nonempty string (-n) => true
force=""
watch=""

# Output style arguments, to be passed to underlying
# libsass complition command.
output_options="--output-style=compressed"

# Parse arguments and options.
while [ $# -gt 0 ]; do
	case $1 in
		-n|--node-modules)
			shift
			if [ $# -eq 0 ]; then
				echo "Error: Missing value for -n/--node-modules"
				echo "$USAGE"
				exit 1
			fi
			node_modules_path="$1"
			shift
			;;
		-w|--watch)
			watch="T"
			shift
			;;
		-f|--force)
			force="T"
			shift
			;;
		-d|--debug)
			output_options="--output-style=nested"
			# TODO: When moving from `sass.compile(...)` to `sassc`, we had to drop
			#       the " --source-comments" option here because it is not available
			#       in libsass==0.10. After upgrading to libsass>=0.11, we should
			#       add back " --source-comments" here.
			shift
			;;
		--dry)
			rm="echo rm"
			sassc="echo sassc"
			rtlcss="echo rtlcss"
			shift
			;;
		-h|--help)
			echo "$USAGE"
			exit 0
			;;
		-*)
			echo "Error: Unrecognized option: $1"
			echo "$USAGE"
			exit 1
			;;
		*)  # Positional arguments. Can be supplied before, after, or between options.
			# First argument: system
			if [ -z "$system" ] ; then
				if [ "$1" = "lms" ] || [ "$1" = "cms" ] ; then
					system="$1"
				else
					echo "Error: expected 'lms' or 'cms' $1"
					echo "$USAGE"
					exit 1
				fi
			# Second argument: theme_dir
			elif [ -z "$theme_dir" ] ; then
				theme_dir="$1"
			# Three or more arguments is an error.
			else
				echo "Error: unexpected argument: $1"
				echo "$USAGE"
				exit 1
			fi
			shift
			;;
	esac
done

# Input validation
if [ -z "$system" ]; then
	echo "Error: must specify 'lms' or 'cms'"
	echo "$USAGE"
	exit 1
fi
if [ -n "$theme_dir" ] && ! [ -d "$theme_dir" ]; then
	echo "Error: provided theme directory is not a directory: $theme_dir"
	echo "$USAGE"
	exit 1
fi 

compile_dir ( ) {
	scss_src="$1"
	css_dest="$2"
	include_path_options="$3"

	if [ -n "$force" ] ; then
		$rm -f "$css_dest/*.css"
	fi

	# Navigate into sass_src and recursively print out relative paths for all SCSS
	# files, excluding underscore-prefixed ones.
	for relpath in $(cd "$scss_src" && find . \( -name \*.scss -and \! -name _\* \)) ; do

		# Compile one SCSS file into a CSS file.
		# Note that sassc's $..._options arguments are not quoted, because they
		# may contain multiple arguments, which we want to split apart rather than
		# pass as one big argument. Shellcheck is not a fan of this, so:
		#     shellcheck disable=2086
		set -x
		$sassc $output_options $include_path_options "$scss_src/$relpath" "$css_dest/$relpath"
		set +x

		# Generate converted RTL css too, if relevant.
		reldir="$(dirname relpath)"
		filename_no_ext="$(basename relpath | sed -n 's/.scss$//p')"
		case "$filename_no_ext" in
			*-rtl)
				# SCSS is already RTL; no need to generate extra RTL file.
				;;
			*)
		 		# shellcheck disable=2086
				echo TODO $rtlcss "$css_dest/$reldir/${filename_no_ext}.css" "$css_dest/$reldir/{$filename_no_ext}-rtl.css"
				;;
		esac
	done
}
echo "-------------------------------------------------------------------------"
if [ -n "$watch" ] ; then
	echo "Watching $system sass for changes..."
	echo "ERROR: watching is not yet implemented"
	exit 1
else
	echo "Compiling $system sass..."
fi
echo "  Working directory     : $(pwd)"
echo "-------------------------------------------------------------------------"

common_include_paths=\
"--include-path=common/static\
 --include-path=common/static/sass\
 --include-path=$node_modules_path\
 --include-path=$node_modules_path/@edx\
"
system_include_paths=\
"$common_include_paths\
 --include-path=$system/static/sass\
 --include-path=$system/static/sass/partials\
 --include-path=lms/static/sass/partials\
"
theme_system_include_paths=\
"$system_include_paths\
 --include-path=$theme_dir/$system/static/sass/partials\
"
theme_certificate_include_paths=\
"$common_include_paths\
 --include-path=$theme_dir/lms/static/sass\
 --include-path=$theme_dir/lms/static/sass/partials\
"

if [ -n "$theme_dir" ] ; then
	# Compile built-in SCSS into theme's CSS dir.
	compile_dir \
		"$system/static/sass" \
		"$theme_dir/$system/static/css" \
		"$theme_system_include_paths"
	# Now override some or all of the built-in CSS by compiling the 
	# theme's SCSS into its CSS dir.
	compile_dir \
		"$theme_dir/$system/static/sass" \
		"$theme_dir/$system/static/css" \
		"$theme_system_include_paths"
	if [ "$system" = "lms" ] ; then
		# Finally, for LMS only, compile the theme's certificates
		# SCSS into its certificates CSS dir.
		compile_dir \
			"$theme_dir/lms/static/certificates/sass" \
			"$theme_dir/lms/static/certificates/css" \
			"$theme_certificate_include_paths"
	fi
else
	# Compile built-in SCSS into CSS dir.
	compile_dir \
		"$system/static/sass" \
		"$system/static/css" \
		"$system_include_paths"
	if [ "$system" = "lms" ] ; then
		# For LMS only, compile built-in certificate SCSS.
		compile_dir \
			"lms/static/certificates/sass" \
			"lms/static/certificates/css" \
			"$system_include_paths"
	fi
fi


echo "-------------------------------------------------------------------------"
echo "Done compiling $system sass."
echo "-------------------------------------------------------------------------"
