"""RAG 백엔드 패키지 (오프라인 퍼징 PC).

이 파일이 **비어 있지 않게** 존재해야 하는 이유
------------------------------------------------
`__init__.py` 가 없으면 `rag` 는 namespace package 가 된다. 그러면 `sys.path` 맨 앞에
`PC_Sampling` 을 넣어도 import 가 거기서 끝나지 않는다 — namespace portion 으로만
기록하고 **탐색을 계속**해서, 뒤쪽 경로에 `__init__.py` 를 가진 다른 `rag` 패키지가
있으면 그쪽이 이긴다. 결과는 `ModuleNotFoundError: No module named 'rag.vllm_client'`
이고, 정작 `rag` 자체는 import 되므로 원인이 잘 안 보인다.

정규 패키지로 두면 첫 경로에서 바로 확정된다. 어떤 `rag` 가 잡혔는지 확인하려면:

    python3 -c "import rag; print(rag.__file__)"
"""
