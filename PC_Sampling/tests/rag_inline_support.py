"""Load exactly the support code which the installer embeds in the online guide."""
import importlib.util
from pathlib import Path
from types import ModuleType

path = Path(__file__).resolve().parents[1] / 'tools' / 'install_rag_query.py'
spec = importlib.util.spec_from_file_location('rag_inline_installer_test', path)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
query_module = ModuleType('inline_guide_test')
exec(compile(installer.INLINE_SOURCE, '<inlined guide support>', 'exec'), query_module.__dict__)
extract_query = query_module._rag_extract_query
prepare_query = query_module._rag_prepare_query
extract_search_context = query_module._rag_extract_search_context
generate_with_rag = query_module._rag_generate_with_rag
RagSearchError = query_module._rag_RagSearchError
