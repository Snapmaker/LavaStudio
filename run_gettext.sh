#!/bin/sh

#  Snapmaker_Orca gettext
#  Created by Snapmaker on 04/11/24.
#

# Check for --full argument
FULL_MODE=false
for arg in "$@"
do
    if [ "$arg" = "--full" ]; then
        FULL_MODE=true
    fi
done

if $FULL_MODE; then
    xgettext --keyword=L --keyword=_L --keyword=_u8L --keyword=L_CONTEXT:1,2c --keyword=_L_PLURAL:1,2 --add-comments=TRN --from-code=UTF-8 --no-location --debug --boost -f ./localization/i18n/list.txt -o ./localization/i18n/Snapmaker_Orca.pot
    python3 scripts/HintsToPot.py ./resources ./localization/i18n
fi


echo "$0: working dir = $PWD"
pot_file="./localization/i18n/Snapmaker_Orca.pot"
for dir in ./localization/i18n/*/
do
    dir=${dir%*/}      # remove the trailing "/"
    lang=${dir##*/}    # extract the language identifier

    if [ -f "$dir/Snapmaker_Orca_${lang}.po" ]; then
        if $FULL_MODE; then
            msgmerge -N -o "$dir/Snapmaker_Orca_${lang}.po" "$dir/Snapmaker_Orca_${lang}.po" "$pot_file"
        fi
        mkdir -p "resources/i18n/${lang}"
        msgfmt --check-format -o "resources/i18n/${lang}/Snapmaker_Orca.mo" "$dir/Snapmaker_Orca_${lang}.po"
        # Check the exit status of the msgfmt command
        if [ $? -ne 0 ]; then
            echo "Error encountered with msgfmt command for language ${lang}."
            exit 1  # Exit the script with an error status
        fi
    fi
done
