cmake_minimum_required(VERSION 3.10.2)

# 代理入口：包含真正的构建逻辑
# 注意：此处用相对路径 from app/ -> cpp/
include(${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/CMakeLists.txt)
