+++
title = '基于Python与K-Means的自动化视频分类方法'
date = 2024-09-21T01:43:21.619108+08:00
draft = false
+++

> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# __实现过程__


1\. 特征提取：使用预训练的 InceptionV3 模型，从视频的若干帧中提取高维的视觉特征。将每个视频的所有帧特征取平均值，生成一个固定长度的特征向量来表示该视频。

2\. 聚类：通过 K-Means 的聚类结果，每个视频被分配了一个簇标签，代表该视频与哪些视频在特征上最相似。

3\. 分类整理：最后根据簇标签，将视频移动到相应的分类文件夹中，每个文件夹对应一个簇。

## __InceptionV3 模型__


InceptionV3 是一种用于图像分类和特征提取的深度学习模型，它是Inception 系列模型的第三个版本，由 Google 在 2015 年提出。

它最初是作为图像分类任务的一个模型，能够将图像分类到 1000 个类别中（如狗、猫、汽车等）。通过去除模型的最后几层（分类部分），可以将 InceptionV3 用作特征提取器。

## __簇__


簇是聚类算法的核心概念，表示数据中相似的子集，目的是将无标签的数据点分组。

## __K-Means__


K-Means 是一种常用的无监督聚类算法，它的目标是将数据点分成 K 个簇（Cluster），使得每个簇内的数据点尽可能接近同一个中心（即簇的质心）。

算法的核心思想是通过迭代的方式找到 K 个最优的簇质心，并根据这些质心将数据进行分组。

# __源码__


## __1\. 安装依赖库__


```
pip install moviepy scikit-learn tensorflow opencv-python
```

## __2\. 实现代码__


```
import os
import numpy as np
import cv2
from moviepy.editor import VideoFileClip
from sklearn.cluster import KMeans
from tensorflow.keras.applications import InceptionV3
from tensorflow.keras.applications.inception_v3 import preprocess_input
from tensorflow.keras.preprocessing import image
from tensorflow.keras.models import Model
from shutil import move

# 提取视频的帧作为特征
def extract_video_features(video_path, model, frame_interval=30):
    video = VideoFileClip(video_path)
    frame_count = 0
    features = []

    for frame in video.iter_frames(fps=1):  # 以每秒一帧的速度获取帧
        if frame_count % frame_interval == 0:
            # Resize frame to match model input size (299x299 for InceptionV3)
            img = cv2.resize(frame, (299, 299))
            img = image.img_to_array(img)
            img = np.expand_dims(img, axis=0)
            img = preprocess_input(img)

            # 提取特征
            feature = model.predict(img)
            features.append(feature.flatten())

        frame_count += 1

    # 取视频的所有帧特征的均值作为视频的最终特征
    return np.mean(features, axis=0)

# 批量提取目录下所有视频的特征
def extract_features_for_all_videos(input_dir, model, frame_interval=30):
    video_features = []
    video_files = []

    for filename in os.listdir(input_dir):
        if filename.endswith(".mp4"):  # 你可以根据需要修改文件格式
            video_path = os.path.join(input_dir, filename)
            print(f"正在处理视频: {filename}")
            features = extract_video_features(video_path, model, frame_interval)
            video_features.append(features)
            video_files.append(filename)

    return np.array(video_features), video_files

# 对视频进行聚类
def cluster_videos(video_features, num_clusters=3):
    kmeans = KMeans(n_clusters=num_clusters, random_state=42)
    kmeans.fit(video_features)
    return kmeans.labels_

# 将视频分类到不同的文件夹
def classify_videos(input_dir, output_dir, video_files, labels):
    for label, filename in zip(labels, video_files):
        output_folder = os.path.join(output_dir, f"cluster_{label}")
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        input_path = os.path.join(input_dir, filename)
        output_path = os.path.join(output_folder, filename)

        move(input_path, output_path)
        print(f"已将视频 {filename} 移动到 {output_folder}")

# 主函数
def main(input_dir, output_dir, num_clusters=3, frame_interval=30):
    # 加载预训练的InceptionV3模型，并去掉顶层的分类部分，只用来提取特征
    base_model = InceptionV3(weights='imagenet')
    model = Model(inputs=base_model.input, outputs=base_model.get_layer('avg_pool').output)

    # 提取所有视频的特征
    video_features, video_files = extract_features_for_all_videos(input_dir, model, frame_interval)

    # 对视频进行聚类
    labels = cluster_videos(video_features, num_clusters)

    # 将视频移动到相应的分类文件夹
    classify_videos(input_dir, output_dir, video_files, labels)

# 示例调用
input_directory = "path/to/input_videos"
output_directory = "path/to/output_videos"
main(input_directory, output_directory, num_clusters=30, frame_interval=30)
```

## __3\. 代码说明__


1\. extract_video_features：从每个视频中提取帧，使用 InceptionV3 模型提取每个帧的特征，并最终取所有帧特征的平均值作为该视频的代表特征。

2\. extract_features_for_all_videos：批量提取目录中所有视频的特征。

3\. cluster_videos：使用 K-Means 聚类算法对视频进行分类，将相似的视频聚到一起。

4\. classify_videos：将视频根据聚类结果移动到不同的分类文件夹。

5\. main：主函数，负责加载模型、提取特征、聚类以及将视频分类。

## __4\. 调用说明__


1\. input_directory: 视频所在的输入文件夹。

2\. output_directory: 输出文件夹，程序会根据聚类结果创建不同的文件夹，将相似的视频分类进去。

3\. num_clusters: 要分类的类别数，即希望将视频分为多少类。

4\. frame_interval: 每隔多少帧提取一次特征帧。值越大，提取帧的间隔越大。


源码地址：[https://github.com/CYRUS-STUDIO/classify-videos-kmeans-python](https://github.com/CYRUS-STUDIO/classify-videos-kmeans-python)


               

