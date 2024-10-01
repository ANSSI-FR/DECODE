"""File graph class."""

from collections import defaultdict
from pathlib import PureWindowsPath
from typing import Optional, Tuple, Union

import graphviz
import networkx as nx
import numpy as np
import pandas as pd
from typing_extensions import Self


COLORS = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"]

CHAR_COLON = "&#58;"
CHAR_LT = "&#60;"
CHAR_GT = "&#62;"
CHAR_AND = "&#38;"
CHAR_BACKSLASH = "&#92"


def escape_special_characters(content: str) -> str:
    """Replaces special characters with their encoding for HTML content
    embedded in graphs rendered using Graphviz.

    Arguments:
    ---------
    content : str
        HTML content to sanitize.

    Returns:
    -------
    sanitized_content : str
        Sanitized version of the input, where special characters have
        been escaped.

    """
    return (
        content.replace("&", CHAR_AND)
        .replace("\\", CHAR_BACKSLASH)
        .replace(":", CHAR_COLON)
        .replace("<", CHAR_LT)
        .replace(">", CHAR_GT)
    )


def relative_file_path(
    fname: Union[PureWindowsPath, str], dir_path: str
) -> Tuple[str, str]:
    """Returns the path from a given directory to one of its descendent
    files as well as the name of the file.

    Arguments:
    ---------
    fname : str or PureWindowsPath
        Full path to the file.
    dir_path : str
        Full path to the directory.

    Returns:
    -------
    base : str
        Path from the directory to the file's parent directory.
    name : str
        Name of the file.

    """
    path = PureWindowsPath(fname).relative_to(dir_path)
    base = "/".join(path.parts[:-1]) + "/"
    name = path.parts[-1]
    return base, name


class SimpleFileGraph(nx.DiGraph):
    """Tree-based representation of a set of files and their parent
    directories.
    Includes graph-oriented anomaly detection algorithms as well as
    a visualization function.
    This class extends the DiGraph class from NetworkX and uses this
    class' attributes and methods for all graph operations.

    """

    def __init__(self, paths: Optional[pd.Series] = None):
        super().__init__()
        if paths is not None:
            for _path in paths:
                path = PureWindowsPath(_path)
                dirs = [str(p) for p in path.parents][::-1]
                for i, d in enumerate(dirs):
                    self.add_node(d, type="dir", depth=i)
                self.add_node(str(path), type="file", name=path, depth=len(dirs))
                to_add = [(dirs[i], dirs[i + 1]) for i in range(len(dirs) - 1)] + [
                    (dirs[-1], str(path))
                ]
                self.add_edges_from(to_add)

    def coarsened_tree(
        self,
        max_nodes: int = 40,
        min_proportion: float = 0,
        file_subset: Optional[list] = None
    ) -> Self:
        """Returns a new instance of SimpleFileGraph containing the same
        files as `self` but with less directories.
        The remaining directories are selected using a simple greedy
        algorithm: at each iteration, one of the already added
        directories is selected and all its child directories are
        added to the new tree.
        The selected directory is the one that maximizes the following
        criterion: the total number of descendent files (including
        those located in subdirectories) divided by the number of new
        directories that would be added to the new tree.
        The algorithm starts with only the root node and stops when the
        number of added directories is greater than `max_nodes`.
        Finally, all file nodes are added to the new tree as children
        of their closest parent directory.

        Arguments:
        ---------
        max_nodes : int, default=40
            Stopping criterion for the tree coarsening algorithm.
            The algorithm stops when there are more than `max_nodes`
            directories in the coarsened tree.
        min_proportion : float, default=0
            Minimum proportion of the total number of descendent files
            that must be descendents of a child directory for it to be
            added to the coarsened tree.
            If `min_proportion` is greater than 0, when child
            directories of a given parent directory are added to the
            coarsened tree, only those whose descendent files account
            for a fraction greater than `min_proportion` of the number
            of descendent files of the parent directory are added.
            The other child directories are merged and added as a
            single node.
        file_subset : list, default=None
            Subset of files from `self` that should be prioritized
            when adding subdirectories to the coarsened tree.
            Specifically, the instead of considering the total number
            of descendent files when choosing the leaf of the current
            coarsened tree whose children should be added, only the
            files belonging to `file_subset` are accounted for.
            If None, all files are equally important.

        Returns:
        -------
        coarsened : SimpleFileGraph
            Coarsened tree with the same file nodes as `self`.

        """
        coarsened = SimpleFileGraph()
        root = self.get_root()
        coarsened.add_node(root, **self.nodes[root])
        if file_subset is not None:
            subtree = SimpleFileGraph(pd.Series(file_subset))
        else:
            subtree = None
        # Select the directories that will be added to the coarsened
        # tree
        while coarsened.number_of_nodes() < max_nodes:
            # Fetch all directories that are leaves of the current
            # coarsened tree
            leaves = [
                n
                for n in coarsened.nodes()
                if coarsened.out_degree(n)
                == 0  # the node is a leaf of the coarsened tree
                and coarsened.is_dir(n)  # the node is a directory
                and self.get_children(n)
                is not None  # the node has children in the original tree
                and len([
                    d for d in self.get_children(n) if self.is_dir(d)
                ])
                > 0  # the node has directories among its children
            ]
            if len(leaves) == 0:
                # If there are no more candidate nodes, break the loop
                break
            # Compute a score for each candidate directory to select
            # the one whose subdirectories will be added to the
            # coarsened tree
            scores = {
                leaf: self._leaf_priority_score(leaf, min_proportion, subtree)
                for leaf in leaves
            }
            # Select the candidate directory with the highest score
            leaves.sort(key=lambda n: scores[n])
            best_leaf = leaves[-1]
            # Fetch subdirectories of the selected candidate and add
            # them to the coarsened tree
            children = [
                d
                for d in self.get_children(best_leaf)
                if self.is_dir(d)
            ]
            if subtree is None or subtree.has_node(best_leaf):
                tree = self if subtree is None else subtree
                thresh = min_proportion * sum(
                    tree.num_descendent_files(c)
                    if tree.has_node(c) else 0
                    for c in children
                )
            else:
                # If best_leaf is not in the subtree containing the selected
                # files, then no remaining leaf with subdirectories has
                # selected files among its descendents, thus we can stop here
                break
            hidden = []
            for c in children:
                if tree.has_node(c) and tree.num_descendent_files(c) >= thresh:
                    # If the subdirectory has enough descendent files,
                    # add it to the coarsened tree
                    coarsened.add_node(c, **self.nodes[c])
                    coarsened.add_edge(best_leaf, c)
                else:
                    # If the subdirectory has too few descendent files,
                    # add it to the list of directories that will be
                    # merged into a single node
                    hidden.append(c)
            if len(hidden) > 0:
                # If there are subdirectories to merge, create a node
                # to represent them
                node = f"OTHER-{best_leaf}"
                coarsened.add_node(
                    node,
                    content=hidden,
                    name="*",
                    depth=self.nodes[best_leaf]["depth"] + 1,
                    type="merged_dirs",
                )
                coarsened.add_edge(best_leaf, node)
        # Add files to the coarsened tree
        nodes = list(coarsened.nodes())
        for n in nodes:
            if coarsened.is_merged_dirs(n):
                # If the current node represents merged directories,
                # fetch the descendent files of all these directories
                files = [
                    f
                    for d in coarsened.nodes[n]["content"]
                    for f in self.get_descendent_files(d)
                ]
            elif coarsened.out_degree(n) == 0:
                # If the current node is a leaf of the coarsened tree,
                # fetch its descendent files
                files = self.get_descendent_files(n)
            else:
                # If the current node has child directories in the
                # coarsened tree, fetch only the files that are its
                # direct children
                files = [
                    f for f in self.get_children(n) if self.is_file(f)
                ]
            for f in files:
                # Add the fetched files as children of the current node
                # in the coarsened tree
                coarsened.add_node(f, **self.nodes[f])
                coarsened.add_edge(n, f)
        return coarsened

    def draw(
        self,
        displayed_files: Optional[Union[list, dict]] = None,
        class_colors: Optional[Union[list, dict]] = None,
        displayed_file_color: str = "red",
        max_displayed_files: int = 35,
        max_name_length: int = 25,
        display_full_path: bool = True,
        filename: Optional[str] = None,
    ) -> graphviz.Digraph:
        """Generates DOT language source code for visualizing the file
        tree using Graphviz.
        All directories are displayed, as well as some specific files
        passed as arguments.
        The resulting tree can thus be quite large and complex;
        consider building a simpler tree using `self.coarsened_tree()`
        first.

        Arguments:
        ---------
        displayed_files : list or dict, default=None
            Specifies which files should be displayed.
            In addition, a dictionary can be passed to include
            addtional information about these files.
            This dictionary should have classes as keys and lists of
            files belonging to each class as values.
            The class (or classes) of each file will then be displayed
            next to its name.
            The `class_colors` argument can also be used to assign a
            color to each class.
        class_colors : list or dict, default=None
            Assigns colors to the classes specified by the
            `displayed_files` argument.
            See the Graphviz documentation for the supported color
            formats.
            If a list is passed, the colors are assigned to the classes
            sorted in alphabetical order.
            If a dict is passed, its keys should be the names of the
            classes, with the corresponding colors as values.
            The default value is None, and default colors are then
            used.
        displayed_file_color : str, default='red'
            Color to use for the name of the displayed files.
            See the Graphviz documentation for the supported color
            formats.
        max_displayed_files : int, default=25
            Maximum number of files displayed in a single directory (a
            low value avoids clutter in the visualization, at the cost
            of some information loss).
        max_name_length : int, default=25
            Maximum length of a directory name.
            Directory names longer than `max_name_length` are truncated
            in the visualization.
        display_full_path : bool, default=True
            If true, the full relative path of each displayed file
            w.r.t. the directory in which it is displayed is shown.
            Otherwise, only the name of the file is displayed.
            This is only useful when drawing a coarsened file tree,
            where some intermediate subdirectories have been removed.
        filename : str, default=None
            Name used when creating the DOT source file and the PDF
            file containing the visualization.
            If None, a default name is used.

        Returns:
        -------
        g : graphviz.Digraph
            Object containing the DOT language representation of the
            file tree.

        """
        if displayed_files is None:
            displayed_files = []
        if filename is None:
            filename = "file_tree"
        g = graphviz.Digraph(filename)
        # Create an ID for each directory
        dirs = {
            n for n in self.nodes() if self.is_dir(n) or self.is_merged_dirs(n)
        }
        node_index = dict(zip(sorted(dirs), range(len(dirs))))
        # Get the files that will be displayed
        if isinstance(displayed_files, list):
            displayed_set = set(displayed_files)
        elif isinstance(displayed_files, dict):
            displayed_set = set().union(*[set(x) for x in displayed_files.values()])
            # Retrieve the classes each file belongs to,
            # as well as the colors assigned to them.
            # file_class maps each displayed file to an
            # HTML representation of its class identifiers
            file_class = defaultdict(str)
            classes = sorted(displayed_files.keys())
            if class_colors is None:
                class_colors = COLORS
            for i, k in enumerate(classes):
                if isinstance(class_colors, list):
                    col = class_colors[i % len(class_colors)]
                elif isinstance(class_colors, dict):
                    col = class_colors[k]
                else:
                    raise TypeError(
                        "class_colors must be a list or a dict, got "
                        f"{type(class_colors)} instead"
                    )
                class_tag = f'<font color="{col.lower()}">{k}</font>'
                for fname in displayed_files[k]:
                    file_class[fname] += class_tag
        else:
            raise TypeError(
                "displayed_files must be a list or a dict, got "
                f"{type(displayed_files)} instead"
            )
        # Add edges between directories and their subdirectories
        for u, v in self.edges:
            if u in dirs and v in dirs:
                g.edge(str(node_index[u]), str(node_index[v]))
        # Add displayed files as HTML content in the corresponding
        # directories
        for d in dirs:
            # Get files
            if self.get_children(d) is None:
                children = []
            else:
                children = [
                    n for n in self.get_children(d) if self.is_file(n)
                ]
            size = len(children)
            # Set the name of the directory node
            if self.is_dir(d):
                # If d is an actual directory in an original file tree
                # (i.e., not a pseudo-directory in a coarsened tree),
                # use its path as name
                name = PureWindowsPath(d).parts[-1]
                if name == "\\":
                    name = "ROOT"
                # Case of C:\
                elif name.endswith("\\"):
                    name = name[:-1]
            else:
                # If d represents merged directories in a coarsened
                # file tree, use its 'name' attribute
                name = self.nodes[d]["name"]
            if len(name) > max_name_length:
                name = name[:max_name_length] + " [...]"
            if size == 0:
                # No files => nothing to do
                g.node(str(node_index[d]), label=name)
            else:
                # Get the files that should be displayed among the
                # directory's children
                displayed_file_names = displayed_set.intersection(
                        {self.nodes[c]["name"] for c in children}
                )
                displayed_list = sorted(displayed_file_names)[:max_displayed_files]
                # Build the HTML representation of the displayed files,
                # starting with an empty table with the directory's
                # name as header
                label_tab = (
                    "<"
                    '<table cellborder="0" cellpadding="4">'
                    '<th><td bgcolor="#023e8a">'
                    '<font color="white">'
                    f"{escape_special_characters(name)} ({size})"
                    "</font>"
                    "</td></th>"
                )
                if display_full_path:
                    # Build the relative paths of the displayed files
                    # w.r.t. the current directory
                    displayed_names = [
                        (
                            relative_file_path(fname, self.get_parent(d))
                            if self.is_merged_dirs(d)
                            else relative_file_path(fname, d)
                        )
                        for fname in displayed_list
                    ]
                else:
                    # We only display the file names, so the relative
                    # path is an empty string
                    displayed_names = [
                        ("", PureWindowsPath(fname).parts[-1])
                        for fname in displayed_list
                    ]
                # Add the files to the table
                label_tab += "".join([
                    (
                        "<tr><td>"
                        '<font color="black">'
                        f"<B>({file_class[fname]})</B>"
                        f" {escape_special_characters(rpath)}"
                        "</font>"
                        f'<font color="{displayed_file_color.lower()}">'
                        f"{escape_special_characters(dname)}"
                        "</font>"
                        "</td></tr>"  # If file classes were passed, display them
                        if isinstance(displayed_files, dict)
                        else (  # If no file classes were passed, just display the names
                            "<tr><td>"
                            '<font color="black">'
                            f" {escape_special_characters(rpath)}"
                            "</font>"
                            "<font"
                            f' color="{displayed_file_color.lower()}">'
                            f"{escape_special_characters(dname)}"
                            "</font>"
                            "</td></tr>"
                        )
                    )
                    for fname, (rpath, dname) in zip(displayed_list, displayed_names)
                ])
                # If there are too many files to display in this
                # directory, truncate and add a placeholder
                if len(displayed_list) < len(displayed_names):
                    label_tab += '<tr><td><font color="black">...</font></td></tr>'
                # Close the HTML tags
                label_tab += "</table>>"
                # Add the node data to the graph
                g.node(
                    str(node_index[d]),
                    label=label_tab,
                    shape="box",
                    penwidth="0",
                )
        return g

    def get_parent(self, node: str) -> Union[str, None]:
        """Returns the parent directory of a given node (file or
        directory).
        Returns None if the node has no parent (i.e., it is the root
        of the file tree).

        Arguments:
        ---------
        node : str
            String identifier of the file or directory.

        Returns:
        -------
        parent : str or None
            String identifier of the parent, or None if the parent does
            not exist.

        """
        predecessors = list(self.predecessors(node))
        if len(predecessors) == 0:
            return None
        return predecessors[0]

    def get_children(self, node: str) -> Union[list, None]:
        """Returns the direct children of a given node (typically a
        directory).
        Returns None if the node has no child (e.g. if it is a file).

        Arguments:
        ---------
        node : str
            String identifier of the file or directory.

        Returns:
        -------
        children : list or None
            String identifiers of the node's children, or None if the
            node has no child.

        """
        successors = list(self.successors(node))
        if len(successors) == 0:
            return None
        return successors

    def get_files(self) -> list:
        """Returns all nodes in the tree that represent files.

        Returns:
        -------
        files : list
            String identifiers of all files in the tree.

        """
        files = [n for n in self.nodes if self.is_file(n)]
        return files

    def get_dirs(self) -> list:
        """Returns all nodes in the tree that represent directories.

        Returns:
        -------
        dirs : list
            String identifiers of all directories in the tree.

        """
        dirs = [n for n in self.nodes if self.is_dir(n)]
        return dirs

    def get_descendent_files(self, node: str) -> list:
        """Returns all files among the descendents of a given node
        (typically a directory), including those located multiple
        hops away.
        When called on a file, returns a list containing the file
        itself.

        Arguments:
        ---------
        node : str
            String identifier of the file or directory.

        Returns:
        -------
        descendents : list
            String identifiers of the node's descendents, or of the
            node itself if it is a file.

        """
        if self.is_file(node):
            return [node]
        queue = [node]
        dirs = {node}
        while len(queue) > 0:
            next_dir = queue.pop()
            children = self.get_children(next_dir)
            if children is not None:
                child_dirs = [d for d in children if self.is_dir(d)]
                dirs.update(child_dirs)
                queue += child_dirs
        return [
            f
            for d in dirs
            for f in self.successors(d)
            if self.is_file(f)
        ]

    def get_neighbor_dirs(self, node: str) -> list:
        """Returns all directories located at most one hop away from the
        given node (file or directory), that is, its parent and direct
        children.

        Arguments:
        ---------
        node : str
            String identifier of the file or directory.

        Returns:
        -------
        neighbors : list
            String identifiers of the directories located at most one
            hop away from the given node.

        """
        res = []
        par = self.get_parent(node)
        if par is not None:
            res.append(par)
        children = self.get_children(node)
        if children is not None:
            res += [d for d in children if self.is_dir(d)]
        return res

    def get_root(self) -> str:
        """Returns the string identifier of the root directory.

        Returns:
        -------
        root : str
            String identifier of the root directory.

        """
        dirs = sorted(self.get_dirs(), key=lambda d: self.nodes[d]["depth"])
        return dirs[0]

    def is_dir(self, node: str) -> bool:
        """Checks whether the given node is a directory.

        Arguments:
        ---------
        node : str
            String identifier of the node.

        Returns:
        -------
        is_dir : bool
            True if the node is a directory, else False.

        """
        return self.nodes[node]["type"] == "dir"

    def is_file(self, node: str) -> bool:
        """Checks whether the given node is a file.

        Arguments:
        ---------
        node : str
            String identifier of the node.

        Returns:
        -------
        is_file : bool
            True if the node is a file, else False.

        """
        return self.nodes[node]["type"] == "file"

    def is_merged_dirs(self, node: str) -> bool:
        """Checks whether the given node is a fusion of directories
        in a coarsened tree.

        Arguments:
        ---------
        node : str
            String identifier of the node.

        Returns:
        -------
        is_merged_dirs : bool
            True if the node is a fusion of directories, else False.

        """
        return self.nodes[node]["type"] == "merged_dirs"

    def num_descendent_files(self, node: str) -> int:
        """Returns the total number of files among the descendents of a
        given node (typically a directory), including those located
        multiple hops away.
        When called on a file, returns 1.
        The result is cached in a node attribute called
        `num_descendent_files`.

        Arguments:
        ---------
        node : str
            String identifier of the file or directory.

        Returns:
        -------
        num_descendent_files : int
            Number of descendent files of the given node (1 if the
            node is itself a file).

        """
        if "num_descendent_files" not in self.nodes[node]:
            self.nodes[node]["num_descendent_files"] = len(
                self.get_descendent_files(node)
            )
        return self.nodes[node]["num_descendent_files"]

    def structural_outliers(
        self, max_outliers: int = 30, n_std_deviations: float = 2
    ) -> Tuple[dict, list]:
        """Detects files that are located in isolated regions of the file
        tree.
        Specifically, the score of a file is defined as the product of
        the number of children of each of its parent directories.
        The negative logarithm of this score is returned so that high
        scores correspond to outliers.

        Arguments:
        ---------
        max_outliers : int, default=30
            Maximum rank of a file in the ranking induced by the
            scores for it to be classified as an outlier.
        n_std_deviations : float, default=2.
            A file is classified as an outlier only if its score is
            greater than the average score by at least
            `n_std_deviations` times the empirical standard deviation
            of the scores.

        Returns:
        -------
        scores_dict : dict
            Maps the identifier of each file to its score.
        outliers : list
            Identifiers of the files classified as outliers based on
            the `max_outliers` and `n_std_deviations` arguments.

        """
        target_nodes = self.get_files()
        nodelist = sorted(self.nodes(), key=lambda n: self.nodes[n]["depth"])
        for n in nodelist:
            self.nodes[n]["branch_weight"] = max(self.out_degree(n), 1)
            par = self.get_parent(n)
            if par is not None:
                self.nodes[n]["branch_weight"] *= self.nodes[par]["branch_weight"]
        res = sorted(target_nodes, key=lambda n: -self.nodes[n]["branch_weight"])
        scores = -np.log(
            np.array([self.nodes[n]["branch_weight"] for n in res]).astype(float)
        )
        mean, std = scores.mean(), scores.std()
        outliers = [
            self.nodes[n]["name"]
            for s, n in zip(scores[-max_outliers:], res[-max_outliers:])
            if s > mean + n_std_deviations * std
        ]
        scores_dict = {}
        for file, score in zip(res, scores):
            name = self.nodes[file]["name"]
            scores_dict[name] = score
        return scores_dict, outliers

    def _leaf_priority_score(
        self, leaf: str, min_proportion: float, subtree: Optional[Self] = None
    ) -> float:
        """Scoring function for the tree coarsening algorithm.

        Arguments:
        ---------
        leaf : str
            Node for which the score is computed.
        min_proportion : float
            Minimum proportion of the total number of descendent files
            that must be descendents of a child directory for it to be
            added to the coarsened tree.
        subtree : SimpleFileGraph
            Subtree of the current tree containing the files used for
            calculating the leaf priority score.
            Used to make the tree coarsening algorithm add more details
            around some specified files.

        Returns:
        -------
        score : float
            Priority score of the leaf.

        """
        if subtree is None:
            tree = self
        elif not subtree.has_node(leaf):
            return 0
        else:
            tree = subtree
        # Compute the total number of descendent files of the
        # subdirectories of the current directory
        num_files = tree.num_descendent_files(leaf) - len([
            n
            for n in tree.get_children(leaf)
            if tree.is_file(n)
        ])
        # Get all subdirectories of the current directory
        children = [
            d for d in self.get_children(leaf) if self.is_dir(d)
        ]
        # Compute the number of subdirectories that would be
        # merged into a single nodes because they do not have
        # enough descendent files
        num_hidden_dirs = 0
        for d in children:
            if (
                not tree.has_node(d)
                or tree.num_descendent_files(d) < min_proportion * num_files
            ):
                num_hidden_dirs += 1
        # Compute the number of new nodes that would be added
        # to the coarsened tree: number of subdirectories minus
        # the number of subdirectories that would be merged,
        # plus one (node representing the merged directories)
        # if some subdirectories are merged
        num_children = len(children)
        if num_hidden_dirs > 0:
            num_children -= num_hidden_dirs - 1
        # The score is the number of descendent files divided
        # by the number of nodes that would be added to the
        # coarsened tree
        return num_files / num_children
