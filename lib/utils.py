import shlex
import subprocess

# Minimise likelihood of OS command injection
# into subprocess.popen calls
# TODO: Get rid of this later for the sake of
# better subprocess calls (i.e. shell=False)


def sanitise_shell_command(command):
    return shlex.split(shlex.quote(command))


def package_results(output_dir):
    # Do reporting (take all the output from
    # the prior runs, zip it up)
    tarfile = output_dir.split("/")
    cmd = (
        "tar --warning=no-all -zcf "
        + output_dir
        + tarfile[3]
        + ".tar.gz -C "
        + output_dir
        + " . --exclude="
        + output_dir
        + tarfile[3]
        + ".tar.gz"
    )
    tar_cmd = sanitise_shell_command(cmd)
    p = subprocess.Popen(tar_cmd, shell=True)
    p.wait()
    return p
