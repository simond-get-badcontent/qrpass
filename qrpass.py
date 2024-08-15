#!/usr/bin/python3
"""
A script that creates passwords printed out as QRcode images.
"""

import argparse
import os

# --------------------------------------------------------------------------------------------------
# QRpass
# --------------------------------------------------------------------------------------------------
# QRpass: A simple password generator that prints out generated passwords as a QRcode image
# --------------------------------------------------------------------------------------------------
# Author: Simon Lundmark
# --------------------------------------------------------------------------------------------------
# Changelog:
# 2017-04-26: Created and tested.                                                            //Simon
# 2017-05-02: Slightly improved.                                                             //Simon
# 2017-05-02: Added add_text_to_image and image_factory.                                     //Simon
# 2017-05-12: Added a bunch of new parameter type stuff                                      //Simon
# 2017-10-03: Added -h for help, woha!                                                       //Simon
# 2018-09-19: Some slight changes and general cleanup.                                       //Simon
# 2020-03-16: Adapted it to Python 3                                                         //Simon
# --------------------------------------------------------------------------------------------------
# Install notes: qrcode ("pip3 install qrcode").
# --------------------------------------------------------------------------------------------------
# Current version:
VERSION = "v. 1.3"
# --------------------------------------------------------------------------------------------------
# Usage (use --help for detailed help):
# Example 1: Run with all default values:
# ./QRpass.py
# Example 2: Specifies the password length as 12 characters:
# ./QRpass.py --length 12
# Note: If using arguments results in errors check your own input, there's no input checking here.
# --------------------------------------------------------------------------------------------------
# A note on entropy:
# RFC4086 "Randomness Requirements for Security" suggests that 49 bits of entropy in passwords
# would be okay in cases such as this one, while NIST (NIST Special Publication 800-63B,
# Digital Identity Guidelines) suggests at least 20 bits of entropy for Look-Up secrets (as opposed
# to memorized secrets) which is the kind we're dealing with here, it does also very, very vaguely
# suggest that 112 bits of entropy is considerd as strong (again, in cases such as these).
# This code will issue a warning for passwords falling under the 49 bits mark and consider
# 112 bits of entropy as very strong.
#
# A note on randomness:
# We'll use Pythons (pseudo) random.SystemRandom class as the random number generator, which in turn
# uses the os.urandom() function for generating random numbers from sources provided by the OS.
# On a Linux system the OS source will be /dev/urandom which is deemed as a suitable source
# in this code as it will almost always contain enaugh entropy to generate a large set of
# passwords (in this case) without beeing too determenistic. The check_entropy() function will
# try to look up the size of the OS entropy pool, display the size and warn if too low,
# but currently only supports Linux systems.
# --------------------------------------------------------------------------------------------------

PARSER = argparse.ArgumentParser(
    description='''Generates a clear text password as well as a QR code representation of that password. ''',
    epilog="""For internal use only. Check the --help examples if you get errors.""",
    prog='qrpass')

PARSER.add_argument('--version',
                    action='version',
                    version='%(prog)s 1.3')
PARSER.add_argument('--password',
                    required=False,
                    type=str,
                    default="",
                    help="user defined (static) password (example: 6Uh9m5t=Yj)")
PARSER.add_argument('--length',
                    required=False,
                    type=int,
                    default=12,
                    help="password length in number of characters (example: 16)")
PARSER.add_argument('--filename',
                    required=False,
                    type=str,
                    default="qrcode.png",
                    help="user defined filename (example: qrcode.png)")
PARSER.add_argument('--count',
                    required=False,
                    type=int,
                    default=0,
                    help="number of codes/passwords to be generated (example: 10)")
PARSER.add_argument('--size',
                    required=False,
                    type=int,
                    default=0,
                    help="user defined size of image in pixels (example: 100)")
PARSER.add_argument('--dir',
                    required=False,
                    type=str,
                    default="./",
                    help="user defined directory to save image to (example: qrcodes/)")
PARSER.add_argument('--complexity',
                    required=False,
                    type=int,
                    default=64,
                    help="use the 64 or 88 character set (overridden by --password, example: values '64' or '88')")
ARGS = PARSER.parse_args()


def check_entropy():
    """Check OS entropy pool, currently only works on Linux systems
    and is badly tested."""

    import sys

    os_type = sys.platform
    if "linux" in os_type:
        try:
            with open('/proc/sys/kernel/random/poolsize') as file:
                entropy_pool_size = file.read()
            print("System entropy available:")
            print(entropy_pool_size.rstrip('\n'))
            if entropy_pool_size < 1024:
                print("Warning: The OS entropy pool might be too small.\n")
            if entropy_pool_size >= 2048:
                print("Note: The OS entropy pool is deemed as good.\n")
        except:
            print ("System entropy available:")
            print ("OS determed as", os_type, "but could not look up entropy.\n")


def password_entropy(pass_chars, pass_length):
    """Calcuates the entropy of the generated password."""

    import math

    # Get the number of possible password combinations by
    # raising possible symbols to the power of the password length
    pass_combinations = pass_chars**pass_length

    # Get the strength of a (pseudo) random password by calculating
    # the base-2 logarithm of the number of possible passwords
    pass_entropy = math.log(pass_combinations, 2)

    print("\nEntropy information:")
    print("Total bits of entropy: ", pass_entropy)
    if pass_entropy < 49:
        print("\nNote: \tThe password entropy is deemed as too low,")
        print("\tconsider increasing the password length.")
    if pass_entropy >= 112:
        print("\nNote: Password considerd as:")
        print("[ ]: Good (49-111 bits).")
        print("[X]: Very strong (>= 112 bits).")
    else:
        print("\nNote: Password considerd as:")
        print("[X]: Good (49-111 bits).")
        print("[ ]: Very strong (>= 112 bits).")


def generate_password():
    """Takes care of generating a password (using dev/urandom as entropy source)"""

    import random

    # Password characters based on grc.com/ppp.htm
    # 64 characters (visually recomended):
    char_64 = "!#%+23456789:=?@ABCDEFGHJKLMNPRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # 88 characters (visually aggressive):
    char_88 = "!\"#$%&'()*+,-./23456789:;<=>?@ABCDEFGHJKLMNOPRSTUVWXYZ[\]^_abcdefghijkmnopqrstuvwxyz{|}~"

    password = ""
    password_chars = ""

    if ARGS.password == "":

        if ARGS.password == 88:
            password_chars = char_88
        else:
            password_chars = char_64

        for _ in range(0, ARGS.length):
            password += random.SystemRandom().choice(password_chars)

        print("Generated password (using the", len(str(password_chars)), "character set):")
        print(password)

        password_entropy(len(password_chars), ARGS.length)

    else:
        password = ARGS.password
        print("Generated password (specified by user):")
        print(password)

        print("\nEntropy information:")
        print("Entropy will not be calculated on user specified passwords.")

    return password


def generate_qrcode(filename):
    """Generates the QRcode (a static password can be specified with the -p argument)"""

    from qrcode import QRCode, ERROR_CORRECT_M

    password = generate_password()

    qr_code = QRCode(
        version=4,
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=6
    )

    qr_code.add_data(password)
    qr_code.make()  # This generates the code itself
    img = qr_code.make_image()  # Contains a PIL.Image.Image object

    print("\nGenerated QRcode image file:")
    print(os.getcwd() + "/" + filename)

    img = img.convert('RGB')
    img.save(filename)
    add_password_header(password, filename)  # This adds the password in cleartext on the QRCode image
    add_footer(filename)


def image_manipulation(filename):
    """Resizes the image (scaling size can be specified with the -s argument)"""

    from PIL import Image

    basewidth = ARGS.size  # This is pixels, possibly an args variable
    img = Image.open(filename)
    wpercent = (basewidth / float(img.size[0]))
    hsize = int((float(img.size[1]) * float(wpercent)))
    img = img.resize((basewidth, hsize), Image.ANTIALIAS)
    filename = filename.replace('.png', '-scaled.png')
    img.save(filename, optimize=True, quality=95)

    print("\nRe-scaled QRcode image file (" + str(basewidth) + "px wide).")
    print(os.getcwd() + "/" + filename)


def add_password_header(password, filename):
    """Adds text to image"""

    from PIL import Image, ImageDraw, ImageFont

    img = Image.open(filename)
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype("fonts/courbd.ttf", 30)
    draw.text((60, 0), "Lösenord:", (0, 0, 0), font=font)  # Adds headliner to image.
    draw.text((60, 25), password, (0, 0, 0), font=font)  # Adds generated password to image
    #draw.text((60, 390),"Hostname:",(0,0,0),font=font)  # Adds hostname to image
    img.save(filename)


def add_footer(filename):
    """Adds text to image"""

    from PIL import Image, ImageDraw, ImageFont

    footer = "Obs! 'User must change password ...'\nskall alltid kryssas i."

    img = Image.open(filename)
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype("fonts/courbd.ttf", 15)
    draw.text((60, 390), footer, (0, 0, 0), font=font)  # Adds headliner to image.
    img.save(filename)


def image_factory():
    """Generates the number of QRCodes (specified with the -c argument)"""

    counter = 0
    while counter < ARGS.count:
        counter += 1
        if not ".png" in ARGS.filename:
            ARGS.filename = ARGS.filename + ".png"
        filename = ARGS.filename.replace('.png', '_') + str(counter) + ".png"
        generate_qrcode(filename)
        if ARGS.size != 0:
            image_manipulation(ARGS.filename)

        print("=======================================================================")


# "Clear" the shell:
print("\n" * 100)

print("=======================================================================")
print("QRpass, a QR code password generator " + VERSION)
print("=======================================================================")

# Try to display entropy information first:
check_entropy()

# Handles if filename has been specified or not:
if not ARGS.dir == "":
    ARGS.filename = ARGS.dir + ARGS.filename

# Runs the actual script:
if ARGS.count == 0:
    generate_qrcode(ARGS.filename)
    if ARGS.size != 0:
        image_manipulation(ARGS.filename)
    print("=======================================================================")
else:
    image_factory()
