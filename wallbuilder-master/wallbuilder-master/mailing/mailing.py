#!/usr/bin/env python3
import argparse
import jinja2
import subprocess
import sys

def key_val_pair(string, separator="="):
    key_value = string.split(separator, 2)
    if len(key_value) != 2:
        raise argparse.ArgumentTypeError(
            "key and value must be separated by '=' in {0!r}".format(key_value)
        )
    return tuple(key_value)

class KeyFilePairOpener:
    def __init__(self, mode='r', separator='=', **options):
        self.mode = mode
        self.separator = separator
        self.options = options

    def __call__(self, string):
        key, filename = key_val_pair(string, self.separator)

        if filename == '-':
            if 'r' in self.mode:
                return sys.stdin
            elif 'w' in self.mode:
                return sys.stdout
            else:
                raise ValueError('argument "-" with mode {0!r}'.format(self.mode))

        try:
            return (key, open(filename, self.mode, **self.options))
        except OSError as e:
            raise argparse.ArgumentTypeError(
                "can't open {0!r}: {1}".format(filename, e)
            )


def main():
    parser = argparse.ArgumentParser(
        description=
            "Constructs an e-mail message from a template and sends it using /usr/bin/mail.",
        epilog=
            "The message subject is read from the template, which stores it in the variable "
            "'subject'."
    )
    parser.add_argument(
        "--template", "-t",
        dest='template', required=True, type=argparse.FileType('r'), metavar="FILE",
        help="Loads the template from FILE."
    )
    parser.add_argument(
        "--recipient", "-r",
        dest='recipients', action='append', default=[], metavar="ADDRESS",
        help=
            "Specifies the e-mail address of the recipient of this message. Can be specified "
            "multiple times for multiple recipients."
    )
    parser.add_argument(
        "--sender", "-s",
        dest='sender', metavar="\"NAME <ADDRESS>\"", default=None,
        help=
            "Specifies the name and e-mail address of the recipient of this message."
    )
    parser.add_argument(
        "--value", "-v",
        dest='values', action='append', default=[], type=key_val_pair, metavar="VARIABLE=VALUE",
        help="Assigns VALUE to the template variable VARIABLE."
    )
    parser.add_argument(
        "--value-from-file", "-F",
        dest='values_from_files', action='append', default=[], type=KeyFilePairOpener('r'), metavar="VARIABLE=FILE",
        help="Reads FILE and assigns its contents to the template variable VARIABLE."
    )
    parser.add_argument(
        "--yes", "-Y",
        dest='yeses', action='append', default=[], metavar="VARIABLE",
        help="Assigns the true Boolean value to the template variable VARIABLE."
    )
    parser.add_argument(
        "--no", "-N",
        dest='noes', action='append', default=[], metavar="VARIABLE",
        help="Assigns the false Boolean value to the template variable VARIABLE."
    )
    parser.add_argument(
        "--strict-undefined", "-u",
        action='store_true',
        help=
            "Stops execution if the template attempts to access a variable which is undefined. By "
            "default, undefined variables are considered empty (e.g. '{{ variable }}' is "
            "substituted with nothing and {%% if variable %%} is considered false)."
    )

    args = parser.parse_args()

    with args.template:
        template_body = args.template.read()

    undefined_class = jinja2.Undefined if not args.strict_undefined else jinja2.StrictUndefined

    template = jinja2.Template(template_body, undefined=undefined_class)

    template_vars = {}

    for var, val in args.values:
        template_vars[var] = val

    for var, val_file in args.values_from_files:
        with val_file:
            val = val_file.read()

        template_vars[var] = val

    for var in args.yeses:
        template_vars[var] = True

    for var in args.noes:
        template_vars[var] = False

    try:
        template_module = template.make_module(vars=template_vars)
    except jinja2.exceptions.UndefinedError as e:
        print(
            "Error applying template {0!r}: {1}".format(args.template.name, e),
            file=sys.stderr
        )
        exit(1)

    try:
        subject = template_module.subject
    except AttributeError:
        print(
            "Error: template {0!r} does not set a 'subject' variable!".format(args.template.name),
            file=sys.stderr
        )
        exit(1)

    body = str(template_module)

    if not args.recipients:
        if args.sender:
            print("From: " + args.sender)
        print("Subject: " + subject)
        print()
        print(body)

    else:
        mail_args = [
            "mail",
            "-s", subject,
        ]
        if args.sender is not None:
            mail_args.extend(("-r", args.sender))
        mail_args.extend(args.recipients)

        mail_proc = subprocess.Popen(mail_args, stdin=subprocess.PIPE)
        mail_proc.communicate(body.encode())
        exit(mail_proc.wait())


if __name__ == '__main__':
    main()
