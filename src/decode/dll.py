"""ListDLLs class."""

from pathlib import Path, PureWindowsPath

import pandas as pd


class ListDlls:
    """ListDLLs class.

    Attributes:
    ----------
    data : pd.DataFrame
        ListDLLs DataFrame.
    """

    def __init__(self, data: pd.DataFrame) -> None:
        """Initialize a ListDLLs processing."""
        self.data = data


def read_list_dlls_from_json(dlls_file: Path) -> ListDlls:
    """Process ListDLLs result from improved (JSON file) output.

    Attributes:
    ----------
    dlls_file : Path
        Path of the ListDLLs json file.
    """
    list_dlls_df = pd.read_json(dlls_file, lines=True)
    list_dlls_df = list_dlls_df.rename(
        columns={
            "exec_name:file_name": "exec_name",
            "exec_pid:process_id": "process_id",
        },
    )
    list_dlls_df = list_dlls_df.set_index(
        ["exec_name", "process_id", "cmdline"],
    )
    list_dlls_df = pd.Series(list_dlls_df.dlls).explode().apply(pd.Series).reset_index()
    list_dlls_df = list_dlls_df.rename(
        columns={"size:file_size": "size", "path:file_path": "path"},
    )
    list_dlls_df["warning"] = list_dlls_df.warning_message.notna()
    list_dlls_df = list_dlls_df.drop("warning_message", axis=1)
    list_dlls_df["path"] = [
        PureWindowsPath(x) for x in list_dlls_df.path
    ]
    list_dlls = ListDlls(list_dlls_df.copy())
    return list_dlls


def read_list_dlls_from_txt(dlls_file: Path) -> ListDlls:
    """Process ListDLLs result from raw (TXT file) output.

    Attributes:
    ----------
    dlls_file : Path
        Path of the ListDLLs txt file.
    """
    data_list = []
    with Path.open(dlls_file) as fp:
        # skip file header
        for line in fp:
            if line.startswith("----------"):
                break

        line_to_analyse = True  # True until the EoF
        while line_to_analyse:
            # new process listing
            process_line = fp.readline().rstrip().split(" ")
            if len(process_line) != 3:
                # unexpected process line format
                continue
            process_name = process_line[0]
            process_id = process_line[2].lstrip()

            commandline_line = fp.readline().rstrip()
            command_line = commandline_line[len("Command line: "):]

            # skip the next 2 lines
            fp.readline()
            fp.readline()

            # list modules
            warning_message = ""
            while True:
                mod_line = fp.readline()
                warning = False
                if not mod_line:
                    # end of file
                    line_to_analyse = False
                    break
                if mod_line.startswith("----------"):
                    # end of the modules for the process
                    break
                if mod_line.startswith("  ***"):
                    # information message for suspicious DLL
                    warning_message += mod_line[5:].rstrip()
                    continue
                if mod_line.startswith("*** "):
                    # DLL path
                    mod_line = f"{mod_line[4:].rstrip()}"
                    warning = True

                # extraction of module information
                module_base = mod_line.split(" ")[0]
                mod_line = mod_line[len(module_base):].lstrip()
                module_size = mod_line.split(" ")[0]
                module = mod_line[len(module_size):].lstrip().rstrip()

                # filling data_list with the current module
                data_list.append(
                    {
                        "exec_name": process_name,
                        "process_id": process_id,
                        "cmdline": command_line,
                        "base": module_base,
                        "size": module_size,
                        "path": module,
                        "warning": bool(warning),
                    }
                )
                warning_message = ""
    list_dlls = ListDlls(pd.DataFrame(data_list))
    return list_dlls
