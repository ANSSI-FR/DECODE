"""Statistical functions."""

from typing import Tuple

import numpy as np
import pandas as pd
from scipy.stats import combine_pvalues
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics.pairwise import pairwise_distances
from sklearn.neighbors import NearestNeighbors


def find_epsilon(x: np.ndarray, contamination: float) -> float:
    """Computes epsilon such as (1 - contamination) * 100 %
    of the points have their nearest neighbor within an
    epsilon radius.
    Computes the distance to the nearest neighbor,
    epsilon is equal to the (1 - contamination) * 100
    percentile.

    Arguments:
    ---------
    x : numpy.ndarray
        Data on which you want to apply DBSCAN.
    contamination : float
        Estimated amount of outliers

    Returns:
    -------
    epsilon : float

    """
    p = (1 - contamination) * 100
    nbrs = NearestNeighbors(n_neighbors=2).fit(x)
    distances, indices = nbrs.kneighbors(x)
    # the nearest neighbor is the point itself, at a distance of zero
    # the distance to the nearest neighbor corresponds to the second value
    dist_first_neighbor = distances[:, 1]
    epsilon = float(np.percentile(sorted(dist_first_neighbor), p))
    if epsilon == 0:
        epsilon = 0.001
    return epsilon


def find_min_pts(x: np.ndarray, epsilon: float, contamination: float) -> int:
    """Computation of `min_pts` such as `contamination`% of the
    points have less than `min_pts` points in its epsilon-neighborhood.

    Arguments:
    ---------
    x : numpy.ndarray
        Data on which you want to apply DBSCAN.
    epsilon : float
        Distance.
    contamination : float

    Returns:
    -------
    min_pts : int

    """
    percentage = contamination * 100
    # calculation of the neighbors in an epsilon radius
    neigh = NearestNeighbors(radius=epsilon)
    neigh.fit(x)
    neigh_dist, neigh_ind = neigh.radius_neighbors(x, sort_results=True)
    # number of neighbors for each point
    nb_neigh = [len(i) for i in neigh_dist]
    min_pts = int(np.percentile(nb_neigh, percentage))
    return min_pts


def anomaly_detection(
    x: np.ndarray, contamination: float
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """The anomaly detection is based on two algorithms:
    Isolation Forest and DBSCAN.
    For DBSCAN, `epsilon` and `min_pts` are computed through
    the estimated contamination rate. We also keep the
    distance to the nearest core point as an indicator, the
    greater this distance, the more isolated the file is.

    Arguments:
    ---------
    x : numpy.ndarray
        Data.
    contamination : float
        Estimated amount of outliers.

    Returns:
    -------
    if_scores : numpy.ndarray
        Score assigned by Isolation Forest for each point.
    if_labels : numpy.ndarray
        Label assigned by Isolation Forest for each point.
        `-1` for outliers and `1` for inliers.
    db.labels_ : numpy.ndarray
        Cluster labels assigned by DBSCAN for each point.
        Outliers samples are given the label `-1`.
    dist_first_core_point : numpy.ndarray
        Distance to the nearest core point.
        The greater this distance, the more isolated the
        point is.

    """
    contamination = (contamination * len(x) + 2) / len(x)
    if contamination > 0.5:
        contamination = 0.5
    # Isolation Forest
    iforest = IsolationForest(contamination=contamination, random_state=0).fit(x)
    if_scores = iforest.decision_function(x)
    if_scores = (-(if_scores)) + max(if_scores)
    if_labels = iforest.fit_predict(x)
    # DBSCAN
    epsilon = find_epsilon(x, contamination)
    min_pts = int(find_min_pts(x, epsilon, contamination))
    if min_pts <= 1:
        min_pts = 2
    if min_pts > 10:
        min_pts = 10
    db = DBSCAN(eps=epsilon, min_samples=min_pts).fit(x)
    # distance to the nearest core point
    dist_matrix = pairwise_distances(x[db.core_sample_indices_], x)
    dist_first_core_point = dist_matrix.min(axis=0).copy()
    return if_scores, if_labels, db.labels_, dist_first_core_point


def prob_x(s: np.ndarray) -> list:
    """Return the probability of occurency
    pvaleur = (P[X>=x] + P[X>x])/2.

    Arguments:
    ---------
    s :
        Score of each point.

    Returns:
    -------
    proba : list
        Pvaleur of each score.

    """
    proba = [
        ((s[s >= i].shape[0] / s.shape[0]) + (s[s > i].shape[0] / s.shape[0])) / 2
        for i in s
    ]
    return proba


def fisher(x: pd.Series) -> float:
    """Combine pvalues Fisher's method
    [1] pval, [0] statistic.

    """
    return combine_pvalues(x, method="fisher")[1]
