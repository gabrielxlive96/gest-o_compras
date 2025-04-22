import streamlit as st
import pandas as pd
import json
from datetime import datetime, timedelta
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
import os
import zipfile
import sqlite3
from passlib.hash import bcrypt
from babel.numbers import format_currency
import plotly.express as px
import uuid
import shutil

# Configuração de unidades
UNIDADES = {
    "UPA Cumbica - Guarulhos": {
        "endereco": "R. dos Jesuítas, 533 - Cidade Industrial Satélite de São Paulo, Guarulhos - SP, 07231-060",
        "cnpj": "50.351.626/0015-16"
    },
    "UPA São João - Guarulhos": {
        "endereco": "Estr. Guarulhos-Nazaré, 4130 - Cidade Soberana, Guarulhos - SP, 07162-000",
        "cnpj": "50.351.626/0016-05"
    },
    "P.A Maria Dirce - Guarulhos": {
        "endereco": "R. Ubatã, 154 - Jardim Maria Dirce, Guarulhos - SP, 07173-380",
        "cnpj": "50.351.626/0014-35"
    },
    "HMCA - Guarulhos": {
        "endereco": "R. José Maurício, 191 - Centro, Guarulhos - SP, 07011-060",
        "cnpj": "50.351.626/0007-06"
    }
}

st.set_page_config(page_title="Gerador de OCs com Login", layout="wide")

# Estilo CSS para botões de exclusão
st.markdown("""
    <style>
    .stButton>button[kind="formSubmit"][label="Confirmar Exclusão"] {
        background-color: #E57373;
        color: white;
        border: none;
        border-radius: 4px;
    }
    .stButton>button[kind="formSubmit"][label="Confirmar Exclusão"]:hover {
        background-color: #D32F2F;
    }
    </style>
""", unsafe_allow_html=True)

# Inicializar session_state
if "autenticado" not in st.session_state:
    st.session_state.autenticado = False
    st.session_state.login_time = None
    st.session_state.usuario = ""
    st.session_state.is_admin = False
if "pagina_historico" not in st.session_state:
    st.session_state.pagina_historico = 1
if "filtros_historico" not in st.session_state:
    st.session_state.filtros_historico = {
        "unidade": "Todas",
        "usuario": "Todos",
        "rubrica": "",
        "fornecedor": "",
        "data_inicio": None,
        "data_fim": None
    }

# Função para inicializar o banco de dados SQLite
def init_db():
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ordens_compra (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            usuario TEXT,
            unidade TEXT,
            rubrica TEXT,
            fornecedor TEXT,
            valor_total REAL,
            arquivo TEXT,
            pdf_content BLOB,
            upload_id TEXT,
            itens_json TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orcamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unidade TEXT,
            mes_ano TEXT,
            valor_orcamento REAL,
            UNIQUE(unidade, mes_ano)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notas_fiscais (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            usuario TEXT,
            localizador TEXT,
            data_emissao TEXT,
            data_vencimento TEXT,
            numero_nf TEXT,
            unidade TEXT,
            rubrica TEXT,
            cnpj_fornecedor TEXT,
            fornecedor TEXT,
            valor_total REAL,
            nf_assinada TEXT,
            observacoes TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissoes_abas (
            username TEXT,
            aba TEXT,
            permissoes TEXT,  -- JSON com detalhes (ex.: {"nivel": "visualizar"})
            PRIMARY KEY (username, aba),
            FOREIGN KEY (username) REFERENCES usuarios(username)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_permissoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            admin_username TEXT,
            target_username TEXT,
            acao TEXT
        )
    """)
    usuarios_iniciais = [
        ("gabriel.melo", bcrypt.hash("senha123"), 1),
        ("anderson.rodrigues", bcrypt.hash("senha123"), 0),
        ("rodrigo.pequeno", bcrypt.hash("senha123"), 0),
        ("karina.poli", bcrypt.hash("senha123"), 0)
        ("joao.chuau", bcrypt.hash("senha123"), 0)
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO usuarios (username, password_hash, is_admin) VALUES (?, ?, ?)",
        usuarios_iniciais
    )
    # Permissões iniciais
    permissoes_iniciais = [
        # gabriel.melo (admin) tem acesso completo a todas
        ("gabriel.melo", "Gerar OCs", '{"nivel": "completo"}'),
        ("gabriel.melo", "Painel de Gastos", '{"nivel": "presente"}'),
        ("gabriel.melo", "Controle de Saldo", '{"nivel": "presente"}'),
        ("gabriel.melo", "Histórico de OCs", '{"nivel": "completo"}'),
        ("gabriel.melo", "Minha Conta", '{"nivel": "presente"}'),
        ("gabriel.melo", "Registro de NFs", '{"nivel": "completo"}'),
        ("gabriel.melo", "Administração de Usuários", '{"nivel": "presente"}'),
        # karina.poli tem acesso a Registro de NFs (completo) e Minha Conta
        ("karina.poli", "Registro de NFs", '{"nivel": "completo"}'),
        ("karina.poli", "Minha Conta", '{"nivel": "presente"}'),
        # outros usuários com acesso padrão
        ("anderson.rodrigues", "Gerar OCs", '{"nivel": "completo"}'),
        ("anderson.rodrigues", "Painel de Gastos", '{"nivel": "presente"}'),
        ("anderson.rodrigues", "Controle de Saldo", '{"nivel": "presente"}'),
        ("anderson.rodrigues", "Histórico de OCs", '{"nivel": "visualizar"}'),
        ("anderson.rodrigues", "Minha Conta", '{"nivel": "presente"}'),
        ("rodrigo.pequeno", "Gerar OCs", '{"nivel": "completo"}'),
        ("rodrigo.pequeno", "Painel de Gastos", '{"nivel": "presente"}'),
        ("rodrigo.pequeno", "Controle de Saldo", '{"nivel": "presente"}'),
        ("rodrigo.pequeno", "Histórico de OCs", '{"nivel": "visualizar"}'),
        ("rodrigo.pequeno", "Minha Conta", '{"nivel": "presente"}'),
    ]
    cursor.executemany(
        "INSERT OR IGNORE INTO permissoes_abas (username, aba, permissoes) VALUES (?, ?, ?)",
        permissoes_iniciais
    )
    conn.commit()
    conn.close()

# Funções de banco de dados
def verificar_login(username, senha):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, is_admin FROM usuarios WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.verify(senha, result[0]):
        return True, bool(result[1])
    return False, False

def cadastrar_usuario(username, senha):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM usuarios WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Usuário já existe."
    password_hash = bcrypt.hash(senha)
    cursor.execute(
        "INSERT INTO usuarios (username, password_hash, is_admin) VALUES (?, ?, 0)",
        (username, password_hash)
    )
    conn.commit()
    conn.close()
    return True, "Usuário cadastrado com sucesso!"

def excluir_usuario(username):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM permissoes_abas WHERE username = ?", (username,))
    cursor.execute("DELETE FROM usuarios WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def alterar_senha(username, nova_senha):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM usuarios WHERE username = ?", (username,))
    if not cursor.fetchone():
        conn.close()
        return False, "Usuário não encontrado."
    password_hash = bcrypt.hash(nova_senha)
    cursor.execute(
        "UPDATE usuarios SET password_hash = ? WHERE username = ?",
        (password_hash, username)
    )
    conn.commit()
    conn.close()
    return True, "Senha alterada com sucesso!"

def verificar_senha_atual(username, senha):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM usuarios WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.verify(senha, result[0]):
        return True
    return False

def listar_usuarios(excluir_self=None):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    query = "SELECT username FROM usuarios"
    if excluir_self:
        query += " WHERE username != ?"
        cursor.execute(query, (excluir_self,))
    else:
        cursor.execute(query)
    usuarios = [row[0] for row in cursor.fetchall()]
    conn.close()
    return sorted(usuarios)

def fazer_backup_banco():
    backup_dir = os.path.expanduser("~/Compras/backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"compras_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
    shutil.copy2("compras.db", backup_path)

def registrar_oc(unidade, rubrica, fornecedor, valor_total, arquivo, pdf_content, usuario, upload_id, itens_json):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO ordens_compra (timestamp, usuario, unidade, rubrica, fornecedor, valor_total, arquivo, pdf_content, upload_id, itens_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (datetime.now().isoformat(), usuario, unidade, rubrica, fornecedor, valor_total, arquivo, pdf_content, upload_id, itens_json)
    )
    conn.commit()
    conn.close()
    st.cache_data.clear()

def excluir_oc(oc_id):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ordens_compra WHERE id = ?", (oc_id,))
    conn.commit()
    conn.close()
    st.cache_data.clear()

@st.cache_data(ttl=300)
def carregar_historico_ocs(_dummy=None):
    conn = sqlite3.connect("compras.db")
    query = """
        SELECT id, unidade, timestamp, usuario, rubrica, fornecedor, valor_total, arquivo, upload_id, itens_json
        FROM ordens_compra
        ORDER BY timestamp DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def obter_pdf_oc(oc_id):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT arquivo, pdf_content FROM ordens_compra WHERE id = ?", (oc_id,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return result[0], result[1]
    return None, None

def registrar_orcamento(unidade, mes_ano, valor_orcamento):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR REPLACE INTO orcamentos (unidade, mes_ano, valor_orcamento)
        VALUES (?, ?, ?)
        """,
        (unidade, mes_ano, valor_orcamento)
    )
    conn.commit()
    conn.close()
    st.cache_data.clear()

@st.cache_data(ttl=300)
def carregar_dados_painel(unidade_filtro=None, data_inicio=None, data_fim=None):
    conn = sqlite3.connect("compras.db")
    query = "SELECT unidade, SUM(valor_total) as total_gasto FROM ordens_compra"
    conditions = []
    params = []
    if unidade_filtro:
        conditions.append("unidade = ?")
        params.append(unidade_filtro)
    if data_inicio:
        conditions.append("timestamp >= ?")
        params.append(data_inicio)
    if data_fim:
        conditions.append("timestamp <= ?")
        params.append(data_fim)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " GROUP BY unidade"
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df

@st.cache_data(ttl=300)
def carregar_dados_saldo(mes_ano=None):
    conn = sqlite3.connect("compras.db")
    query_orcamentos = "SELECT unidade, valor_orcamento FROM orcamentos"
    if mes_ano:
        query_orcamentos += " WHERE mes_ano = ?"
        df_orcamentos = pd.read_sql_query(query_orcamentos, conn, params=[mes_ano] if mes_ano else [])
    else:
        df_orcamentos = pd.read_sql_query(query_orcamentos, conn)

    query_gastos = """
        SELECT unidade, SUM(valor_total) as total_gasto
        FROM ordens_compra
        WHERE strftime('%Y-%m', timestamp) = ?
        GROUP BY unidade
    """
    mes_ano_query = mes_ano or datetime.now().strftime("%Y-%m")
    df_gastos = pd.read_sql_query(query_gastos, conn, params=[mes_ano_query])

    df = pd.DataFrame({"unidade": list(UNIDADES.keys())})
    df = df.merge(df_orcamentos, on="unidade", how="left")
    df = df.merge(df_gastos, on="unidade", how="left")
    df['valor_orcamento'] = df['valor_orcamento'].fillna(0.0)
    df['total_gasto'] = df['total_gasto'].fillna(0.0)
    df['saldo'] = df['valor_orcamento'] - df['total_gasto']
    conn.close()
    return df

def registrar_nf(usuario, localizador, data_emissao, data_vencimento, numero_nf, unidade, rubrica, cnpj_fornecedor, fornecedor, valor_total, nf_assinada, observacoes):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO notas_fiscais (timestamp, usuario, localizador, data_emissao, data_vencimento, numero_nf, unidade, rubrica, 
        cnpj_fornecedor, fornecedor, valor_total, nf_assinada, observacoes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().isoformat(),
            usuario,
            localizador,
            data_emissao,
            data_vencimento,
            numero_nf,
            unidade,
            rubrica,
            cnpj_fornecedor,
            fornecedor,
            valor_total,
            nf_assinada,
            observacoes
        )
    )
    conn.commit()
    conn.close()
    st.cache_data.clear()

@st.cache_data(ttl=300)
def carregar_nfs_usuario(_usuario, _dummy=None):
    conn = sqlite3.connect("compras.db")
    query = """
        SELECT id, timestamp, localizador, data_emissao, data_vencimento, numero_nf, unidade, rubrica, 
               cnpj_fornecedor, fornecedor, valor_total, nf_assinada, observacoes
        FROM notas_fiscais
        WHERE usuario = ?
        ORDER BY timestamp DESC
    """
    df = pd.read_sql_query(query, conn, params=[_usuario])
    conn.close()
    return df

def atualizar_nf(nf_id, localizador, data_emissao, data_vencimento, numero_nf, unidade, rubrica, cnpj_fornecedor, fornecedor, valor_total, nf_assinada, observacoes):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE notas_fiscais
        SET localizador = ?, data_emissao = ?, data_vencimento = ?, numero_nf = ?, unidade = ?, rubrica = ?, 
            cnpj_fornecedor = ?, fornecedor = ?, valor_total = ?, nf_assinada = ?, observacoes = ?
        WHERE id = ?
        """,
        (
            localizador,
            data_emissao,
            data_vencimento,
            numero_nf,
            unidade,
            rubrica,
            cnpj_fornecedor,
            fornecedor,
            valor_total,
            nf_assinada,
            observacoes,
            nf_id
        )
    )
    conn.commit()
    conn.close()
    st.cache_data.clear()

def excluir_nf(nf_id):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM notas_fiscais WHERE id = ?", (nf_id,))
    conn.commit()
    conn.close()
    st.cache_data.clear()

def get_permissoes_usuario(username):
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    cursor.execute("SELECT aba, permissoes FROM permissoes_abas WHERE username = ?", (username,))
    permissoes = {row[0]: json.loads(row[1]) for row in cursor.fetchall()}
    conn.close()
    return permissoes

def atualizar_permissoes_usuario(username, permissoes_dict, admin_username):
    fazer_backup_banco()
    conn = sqlite3.connect("compras.db")
    cursor = conn.cursor()
    # Remover permissões existentes
    cursor.execute("DELETE FROM permissoes_abas WHERE username = ?", (username,))
    # Adicionar novas permissões
    for aba, perms in permissoes_dict.items():
        if perms.get("nivel") != "sem_acesso":
            cursor.execute(
                "INSERT INTO permissoes_abas (username, aba, permissoes) VALUES (?, ?, ?)",
                (username, aba, json.dumps(perms))
            )
    # Registrar no log
    acao = f"Alterou permissões de {username}: {json.dumps(permissoes_dict, ensure_ascii=False)}"
    cursor.execute(
        "INSERT INTO log_permissoes (timestamp, admin_username, target_username, acao) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(), admin_username, username, acao)
    )
    conn.commit()
    conn.close()
    st.cache_data.clear()

@st.cache_data(ttl=300)
def carregar_log_permissoes(_dummy=None):
    conn = sqlite3.connect("compras.db")
    query = """
        SELECT timestamp, admin_username, target_username, acao
        FROM log_permissoes
        ORDER BY timestamp DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# Inicializar banco de dados
init_db()

# Login
if not st.session_state.autenticado:
    st.title("🔐 Login")
    usuario = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        sucesso, is_admin = verificar_login(usuario, senha)
        if sucesso:
            st.session_state.autenticado = True
            st.session_state.usuario = usuario
            st.session_state.is_admin = is_admin
            st.session_state.login_time = datetime.now()
            st.success("Login realizado com sucesso!")
            st.rerun()
        else:
            st.error("Usuário ou senha inválidos.")
    st.stop()

# Verificar timeout de sessão
if st.session_state.autenticado and datetime.now() - st.session_state.login_time > timedelta(minutes=30):
    st.session_state.autenticado = False
    st.session_state.usuario = ""
    st.session_state.is_admin = False
    st.session_state.login_time = None
    st.warning("Sessão expirada. Faça login novamente.")
    st.rerun()

# Cabeçalho com botão de logout
col1, col2 = st.columns([0.85, 0.15])
with col1:
    st.markdown(f"👤 **Usuário logado:** {st.session_state.usuario} {'(Admin)' if st.session_state.is_admin else ''}")
with col2:
    if st.button("Sair"):
        st.session_state.autenticado = False
        st.session_state.usuario = ""
        st.session_state.is_admin = False
        st.session_state.login_time = None
        st.rerun()

# Definir abas disponíveis
todas_abas = {
    "Gerar OCs": ["sem_acesso", "visualizar", "completo"],
    "Painel de Gastos": ["sem_acesso", "presente"],
    "Controle de Saldo": ["sem_acesso", "presente"],
    "Histórico de OCs": ["sem_acesso", "visualizar", "completo"],
    "Minha Conta": ["sem_acesso", "presente"],
    "Registro de NFs": ["sem_acesso", "visualizar", "registrar", "completo"],
    "Administração de Usuários": ["sem_acesso", "presente"]
}

# Obter permissões do usuário
permissoes_usuario = get_permissoes_usuario(st.session_state.usuario)

# Para admins, garantir acesso completo a todas as abas
if st.session_state.is_admin:
    permissoes_usuario = {aba: {"nivel": "completo" if aba in ["Gerar OCs", "Histórico de OCs", "Registro de NFs"] else "presente"} for aba in todas_abas}

# Filtrar abas que o usuário pode ver
tabs = [aba for aba in todas_abas if permissoes_usuario.get(aba, {}).get("nivel", "sem_acesso") != "sem_acesso"]

# Criar abas dinamicamente
tab_dict = {}
if tabs:
    tab_objects = st.tabs(tabs)
    for i, tab_name in enumerate(tabs):
        tab_dict[tab_name] = tab_objects[i]
else:
    st.warning("Você não tem permissão para acessar nenhuma aba.")
    st.stop()

# Mapear abas para variáveis
tab1 = tab_dict.get("Gerar OCs")
tab2 = tab_dict.get("Painel de Gastos")
tab3 = tab_dict.get("Controle de Saldo")
tab4 = tab_dict.get("Histórico de OCs")
tab5 = tab_dict.get("Minha Conta")
tab_nfs = tab_dict.get("Registro de NFs")
tab_admin = tab_dict.get("Administração de Usuários")

# Obter nível de permissão para uso nas abas
perm_gerar_ocs = permissoes_usuario.get("Gerar OCs", {}).get("nivel", "sem_acesso")
perm_historico = permissoes_usuario.get("Histórico de OCs", {}).get("nivel", "sem_acesso")
perm_nfs = permissoes_usuario.get("Registro de NFs", {}).get("nivel", "sem_acesso")

# Aba Gerar OCs
if tab1:
    with tab1:
        st.header("📦 Gerador de Ordens de Compra")
        nome_usuario = st.session_state.usuario
        unidade = st.selectbox("Selecione a Unidade:", list(UNIDADES.keys()), key="unidade_gerar")
        uploaded_file = st.file_uploader("Selecione o arquivo do Mapa de Preços (Excel):", type=["xlsx", "xls"])
        logo_path = "logo.jpeg"

        def gerar_pasta_saida(unidade_nome):
            base_dir = os.path.expanduser("~/Compras")
            data_hoje = datetime.today().strftime("%Y-%m-%d")
            destino = os.path.normpath(os.path.join(base_dir, unidade_nome, data_hoje))
            if not destino.startswith(base_dir):
                raise ValueError("Caminho inválido detectado.")
            os.makedirs(destino, exist_ok=True)
            return destino, data_hoje

        def format_data(grupo):
            grupo = grupo.copy()
            grupo['Total'] = grupo['Quantidade'] * grupo['Valor Unitário']
            valor_total = grupo['Total'].sum()
            valor_total_str = format_currency(valor_total, 'BRL', locale='pt_BR')
            grupo['Valor Unitário'] = grupo['Valor Unitário'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            grupo['Total'] = grupo['Total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            return grupo, valor_total, valor_total_str

        def gerar_pdf_por_grupo(df, unidade, dados_unidade, destino, usuario):
            styles = getSampleStyleSheet()
            wrap_style = ParagraphStyle(name='wrap', fontSize=8, leading=10)
            pdf_files = []
            upload_id = str(uuid.uuid4())
            total_groups = len(df.groupby(["Rubrica", "Fornecedor"]))
            progress_bar = st.progress(0)

            for i, ((rubrica, fornecedor), grupo) in enumerate(df.groupby(["Rubrica", "Fornecedor"])):
                nome_pdf = f"OC_{rubrica}_{fornecedor}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf".replace("/", "-").replace("\\", "-")
                buffer = BytesIO()
                doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=30, rightMargin=30, topMargin=30, bottomMargin=30)
                flowables = []

                if os.path.exists(logo_path):
                    img = Image(logo_path, width=1.8*inch, height=1.2*inch)
                    flowables.append(img)
                else:
                    st.warning("Logo não encontrado. Gerando PDF sem logo.")

                flowables.append(Spacer(1, 8))
                flowables.append(Paragraph(f"<b>Ordem de Compra - {unidade}</b>", styles['Title']))
                flowables.append(Spacer(1, 12))
                flowables.append(Paragraph(f"<b>Rubrica:</b> {rubrica}", styles['Normal']))
                flowables.append(Paragraph(f"<b>Fornecedor:</b> {fornecedor}", styles['Normal']))
                flowables.append(Paragraph(f"<b>Endereço:</b> {dados_unidade['endereco']}", styles['Normal']))
                flowables.append(Paragraph(f"<b>CNPJ:</b> {dados_unidade['cnpj']}", styles['Normal']))
                flowables.append(Paragraph(f"<b>Data de Emissão:</b> {datetime.today().strftime('%d/%m/%Y')}", styles['Normal']))
                flowables.append(Spacer(1, 12))

                grupo, valor_total, valor_total_str = format_data(grupo)
                itens_json = grupo.to_json(orient="records", force_ascii=False)

                colunas = grupo.columns.tolist()
                data = [[Paragraph(str(col), wrap_style) for col in colunas]]
                for row in grupo.values.tolist():
                    data.append([Paragraph(str(cell), wrap_style) for cell in row])

                col_widths = [1.5*inch, 2.5*inch, 1.2*inch, 1.0*inch, 1.2*inch, 1.5*inch, 1.2*inch]
                table = Table(data, colWidths=col_widths, repeatRows=1)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ]))
                flowables.append(table)
                flowables.append(Spacer(1, 18))
                flowables.append(Paragraph(f"<b>O valor total desta ordem de compra é de {valor_total_str}.</b>", styles['Normal']))

                doc.build(flowables)
                pdf_content = buffer.getvalue()
                pdf_files.append((nome_pdf, pdf_content))
                registrar_oc(unidade, rubrica, fornecedor, valor_total, nome_pdf, pdf_content, usuario, upload_id, itens_json)
                progress_bar.progress((i + 1) / total_groups)

            return pdf_files

        if uploaded_file:
            try:
                # Verificar tamanho do arquivo (10MB)
                if uploaded_file.size > 10 * 1024 * 1024:
                    st.error("O arquivo excede o limite de 10MB.")
                    st.stop()

                df = pd.read_excel(uploaded_file)
                required_columns = ["Rubrica", "Fornecedor", "Quantidade", "Valor Unitário"]
                missing_cols = [col for col in required_columns if col not in df.columns]
                if missing_cols:
                    st.error(f"Colunas faltando: {', '.join(missing_cols)}")
                    st.stop()

                # Validação linha a linha
                errors = []
                for idx, row in df.iterrows():
                    if pd.isna(row['Rubrica']) or not isinstance(row['Rubrica'], str):
                        errors.append(f"Linha {idx+2}: 'Rubrica' inválida ou vazia.")
                    if pd.isna(row['Fornecedor']) or not isinstance(row['Fornecedor'], str):
                        errors.append(f"Linha {idx+2}: 'Fornecedor' inválido ou vazio.")
                    if not pd.api.types.is_numeric_dtype(type(row['Quantidade'])) or row['Quantidade'] <= 0:
                        errors.append(f"Linha {idx+2}: 'Quantidade' deve ser um número positivo.")
                    if not pd.api.types.is_numeric_dtype(type(row['Valor Unitário'])) or row['Valor Unitário'] <= 0:
                        errors.append(f"Linha {idx+2}: 'Valor Unitário' deve ser um número positivo.")

                if errors:
                    st.error("Erros encontrados no arquivo:")
                    for err in errors[:5]:
                        st.write(f"- {err}")
                    if len(errors) > 5:
                        st.write(f"...e mais {len(errors)-5} erros.")
                    st.stop()

                st.subheader("Pré-visualização do Arquivo")
                st.dataframe(df.head(10), use_container_width=True)
                if perm_gerar_ocs == "completo":
                    if st.button("Validar e Prosseguir"):
                        st.session_state.df_validado = df
                        st.session_state.unidade_validada = unidade
                        st.success("Arquivo validado! Clique em 'Gerar OCs' para continuar.")
                else:
                    st.info("Você tem permissão apenas para visualizar. Contate um administrador para gerar OCs.")

            except pd.errors.EmptyDataError:
                st.error("O arquivo Excel está vazio.")
            except pd.errors.ParserError:
                st.error("Formato de arquivo inválido. Use um arquivo Excel válido.")
            except Exception as e:
                st.error(f"Erro inesperado: {e}")
                st.stop()

        if "df_validado" in st.session_state and perm_gerar_ocs == "completo":
            if st.button("Gerar Ordens de Compra"):
                with st.spinner("Gerando OCs..."):
                    df = st.session_state.df_validado
                    unidade = st.session_state.unidade_validada
                    dados_unidade = UNIDADES[unidade]
                    destino, data_str = gerar_pasta_saida(unidade)
                    pdfs = gerar_pdf_por_grupo(df, unidade, dados_unidade, destino, nome_usuario)

                    zip_buffer = BytesIO()
                    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
                        for nome_pdf, content in pdfs:
                            zipf.writestr(nome_pdf, content)

                    zip_buffer.seek(0)
                    zip_name = f"{unidade}_{data_str}.zip"
                    st.download_button("📁 Baixar OCs em ZIP", zip_buffer, file_name=zip_name)
                    st.success("OCs geradas com sucesso!")
                    del st.session_state.df_validado
                    del st.session_state.unidade_validada

# Aba Painel de Gastos
if tab2:
    with tab2:
        st.header("📊 Painel de Gastos por Unidade")
        unidade_filtro = st.selectbox("Filtrar por Unidade:", ["Todas"] + list(UNIDADES.keys()), key="unidade_filtro")
        col1, col2 = st.columns(2)
        with col1:
            data_inicio = st.date_input("Data Início", value=None)
        with col2:
            data_fim = st.date_input("Data Fim", value=None)

        unidade_filtro = None if unidade_filtro == "Todas" else unidade_filtro
        data_inicio_str = data_inicio.strftime("%Y-%m-%d") if data_inicio else None
        data_fim_str = data_fim.strftime("%Y-%m-%d") if data_fim else None
        df_painel = carregar_dados_painel(unidade_filtro, data_inicio_str, data_fim_str)

        if df_painel.empty:
            st.info("Nenhum dado disponível para o filtro selecionado.")
        else:
            total_gasto = df_painel['total_gasto'].sum()
            media_por_unidade = df_painel['total_gasto'].mean() if not df_painel.empty else 0
            col_metric1, col_metric2 = st.columns(2)
            col_metric1.metric("Total de Gastos", format_currency(total_gasto, 'BRL', locale='pt_BR'))
            col_metric2.metric("Média por Unidade", format_currency(media_por_unidade, 'BRL', locale='pt_BR'))

            df_painel['total_gasto_fmt'] = df_painel['total_gasto'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            st.subheader("Totais por Unidade")
            st.dataframe(df_painel[['unidade', 'total_gasto_fmt']], use_container_width=True,
                         column_config={"unidade": "Unidade", "total_gasto_fmt": "Total Gasto"})

            fig = px.bar(df_painel, x="unidade", y="total_gasto", title="Gastos por Unidade",
                         labels={"total_gasto": "Total Gasto (BRL)"}, color="unidade",
                         color_discrete_sequence=["#4A90E2", "#7B8A8B", "#E57373"])
            st.plotly_chart(fig, use_container_width=True)

# Aba Controle de Saldo
if tab3:
    with tab3:
        st.header("💰 Controle de Saldo Mensal")
        
        if st.session_state.is_admin:
            st.subheader("Definir Orçamento Mensal")
            with st.form("orcamento_form"):
                unidade_orcamento = st.selectbox("Unidade:", list(UNIDADES.keys()), key="unidade_orcamento")
                col1, col2 = st.columns(2)
                with col1:
                    ano = st.selectbox("Ano:", list(range(2020, 2031)), index=2025-2020, key="ano_orcamento")
                with col2:
                    mes = st.selectbox("Mês:", 
                                      ["01 - Janeiro", "02 - Fevereiro", "03 - Março", "04 - Abril", 
                                       "05 - Maio", "06 - Junho", "07 - Julho", "08 - Agosto", 
                                       "09 - Setembro", "10 - Outubro", "11 - Novembro", "12 - Dezembro"],
                                      index=datetime.now().month-1, key="mes_orcamento")
                valor_orcamento = st.number_input("Valor do Orçamento (R$):", min_value=0.0, step=1000.0)
                submit_button = st.form_submit_button("Salvar Orçamento")
                
                if submit_button and valor_orcamento > 0:
                    mes_ano_str = f"{ano}-{mes[:2]}"
                    registrar_orcamento(unidade_orcamento, mes_ano_str, valor_orcamento)
                    st.success(f"Orçamento de {format_currency(valor_orcamento, 'BRL', locale='pt_BR')} salvo para {unidade_orcamento} em {mes_ano_str}!")
        else:
            st.info("Apenas administradores podem definir orçamentos.")

        st.subheader("Saldos por Unidade")
        col1, col2 = st.columns(2)
        with col1:
            ano_filtro = st.selectbox("Ano:", list(range(2020, 2031)), index=2025-2020, key="ano_filtro")
        with col2:
            mes_filtro = st.selectbox("Mês:", 
                                     ["01 - Janeiro", "02 - Fevereiro", "03 - Março", "04 - Abril", 
                                      "05 - Maio", "06 - Junho", "07 - Julho", "08 - Agosto", 
                                      "09 - Setembro", "10 - Outubro", "11 - Novembro", "12 - Dezembro"],
                                     index=datetime.now().month-1, key="mes_filtro")
        
        mes_ano_filtro_str = f"{ano_filtro}-{mes_filtro[:2]}"
        
        df_saldo = carregar_dados_saldo(mes_ano_filtro_str)
        
        if df_saldo['valor_orcamento'].sum() == 0:
            st.info("Nenhum orçamento definido para o período selecionado.")
        else:
            for _, row in df_saldo.iterrows():
                if row['valor_orcamento'] > 0 and row['saldo'] / row['valor_orcamento'] < 0.1:
                    st.warning(f"⚠️ Saldo crítico para {row['unidade']}: apenas {format_currency(row['saldo'], 'BRL', locale='pt_BR')} restante!")

            df_saldo['valor_orcamento_fmt'] = df_saldo['valor_orcamento'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            df_saldo['total_gasto_fmt'] = df_saldo['total_gasto'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            df_saldo['saldo_fmt'] = df_saldo['saldo'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            df_saldo['status'] = df_saldo['saldo'].apply(lambda x: "🟢 Positivo" if x > 0 else "🔴 Negativo ou Zerado")
            
            st.dataframe(
                df_saldo[['unidade', 'valor_orcamento_fmt', 'total_gasto_fmt', 'saldo_fmt', 'status']],
                use_container_width=True,
                column_config={
                    "unidade": "Unidade",
                    "valor_orcamento_fmt": "Orçamento",
                    "total_gasto_fmt": "Gasto",
                    "saldo_fmt": "Saldo",
                    "status": "Status"
                }
            )

            fig_saldo = px.bar(
                df_saldo,
                x="unidade",
                y=["valor_orcamento", "total_gasto", "saldo"],
                title=f"Saldos por Unidade - {mes_ano_filtro_str}",
                labels={"value": "Valor (BRL)", "variable": "Categoria"},
                barmode="group",
                color_discrete_sequence=["#4A90E2", "#E57373", "#7B8A8B"]
            )
            st.plotly_chart(fig_saldo, use_container_width=True)

# Aba Histórico de OCs
if tab4:
    with tab4:
        st.header("📜 Histórico de Ordens de Compra")
        
        st.subheader("Filtros")
        with st.container():
            df_ocs = carregar_historico_ocs()
            rubricas_unicas = sorted(df_ocs['rubrica'].dropna().unique())
            fornecedores_unicos = sorted(df_ocs['fornecedor'].dropna().unique())
            usuarios_unicos = sorted(listar_usuarios())

            opcoes_unidades = ["Todas"] + list(UNIDADES.keys())
            opcoes_usuarios = ["Todos"] + usuarios_unicos
            opcoes_rubricas = [""] + rubricas_unicas
            opcoes_fornecedores = [""] + fornecedores_unicos

            col1, col2 = st.columns([1, 1])
            with col1:
                unidade_atual = st.session_state.filtros_historico["unidade"]
                if unidade_atual not in opcoes_unidades:
                    unidade_atual = "Todas"
                st.session_state.filtros_historico["unidade"] = st.selectbox(
                    "Unidade:",
                    opcoes_unidades,
                    index=opcoes_unidades.index(unidade_atual),
                    key="unidade_filtro_historico"
                )
                st.session_state.filtros_historico["data_inicio"] = st.date_input(
                    "Data Início",
                    value=st.session_state.filtros_historico["data_inicio"],
                    key="data_inicio_historico"
                )
            with col2:
                usuario_atual = st.session_state.filtros_historico["usuario"]
                if usuario_atual not in opcoes_usuarios:
                    usuario_atual = "Todos"
                st.session_state.filtros_historico["usuario"] = st.selectbox(
                    "Usuário:",
                    opcoes_usuarios,
                    index=opcoes_usuarios.index(usuario_atual),
                    key="usuario_filtro_historico"
                )
                st.session_state.filtros_historico["data_fim"] = st.date_input(
                    "Data Fim",
                    value=st.session_state.filtros_historico["data_fim"],
                    key="data_fim_historico"
                )
            rubrica_atual = st.session_state.filtros_historico["rubrica"]
            if rubrica_atual not in opcoes_rubricas:
                rubrica_atual = ""
            st.session_state.filtros_historico["rubrica"] = st.selectbox(
                "Rubrica (busca):",
                opcoes_rubricas,
                index=opcoes_rubricas.index(rubrica_atual),
                key="rubrica_filtro_historico"
            )
            fornecedor_atual = st.session_state.filtros_historico["fornecedor"]
            if fornecedor_atual not in opcoes_fornecedores:
                fornecedor_atual = ""
            st.session_state.filtros_historico["fornecedor"] = st.selectbox(
                "Fornecedor (busca):",
                opcoes_fornecedores,
                index=opcoes_fornecedores.index(fornecedor_atual),
                key="fornecedor_filtro_historico"
            )

            if st.button("🧹 Limpar Filtros"):
                st.session_state.filtros_historico = {
                    "unidade": "Todas",
                    "usuario": "Todos",
                    "rubrica": "",
                    "fornecedor": "",
                    "data_inicio": None,
                    "data_fim": None
                }
                st.rerun()

        if not df_ocs.empty:
            df_ocs['upload_id'] = df_ocs['upload_id'].fillna("Desconhecido")
            df_ocs['itens_json'] = df_ocs['itens_json'].fillna("[]")
            
            df_filtered = df_ocs.copy()
            if st.session_state.filtros_historico["unidade"] != "Todas":
                df_filtered = df_filtered[df_filtered['unidade'] == st.session_state.filtros_historico["unidade"]]
            if st.session_state.filtros_historico["usuario"] != "Todos":
                df_filtered = df_filtered[df_filtered['usuario'] == st.session_state.filtros_historico["usuario"]]
            if st.session_state.filtros_historico["rubrica"]:
                df_filtered = df_filtered[df_filtered['rubrica'].str.contains(st.session_state.filtros_historico["rubrica"], case=False, na=False)]
            if st.session_state.filtros_historico["fornecedor"]:
                df_filtered = df_filtered[df_filtered['fornecedor'].str.contains(st.session_state.filtros_historico["fornecedor"], case=False, na=False)]
            if st.session_state.filtros_historico["data_inicio"]:
                df_filtered = df_filtered[pd.to_datetime(df_filtered['timestamp']) >= pd.to_datetime(st.session_state.filtros_historico["data_inicio"])]
            if st.session_state.filtros_historico["data_fim"]:
                df_filtered = df_filtered[pd.to_datetime(df_filtered['timestamp']) <= pd.to_datetime(st.session_state.filtros_historico["data_fim"]) + timedelta(days=1)]
            
            if df_filtered.empty:
                st.info("Nenhuma ordem de compra encontrada com os filtros selecionados.")
            else:
                df_groups = df_filtered.groupby('upload_id').agg({
                    'timestamp': 'min',
                    'usuario': 'first',
                    'unidade': 'first',
                    'valor_total': 'sum',
                    'id': 'count'
                }).reset_index()
                df_groups = df_groups.rename(columns={'id': 'num_ocs'})
                df_groups['timestamp'] = pd.to_datetime(df_groups['timestamp']).dt.strftime('%d/%m/%Y %H:%M:%S')
                df_groups['valor_total_fmt'] = df_groups['valor_total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
                
                itens_por_pagina = 10
                total_paginas = (len(df_groups) + itens_por_pagina - 1) // itens_por_pagina
                total_paginas = max(1, total_paginas)
                
                if st.session_state.pagina_historico > total_paginas:
                    st.session_state.pagina_historico = total_paginas
                if st.session_state.pagina_historico < 1:
                    st.session_state.pagina_historico = 1
                    
                inicio = (st.session_state.pagina_historico - 1) * itens_por_pagina
                fim = inicio + itens_por_pagina
                df_groups_paginado = df_groups.iloc[inicio:fim]
                
                total_valor = df_filtered['valor_total'].sum()
                st.metric("Total dos Valores Filtrados", format_currency(total_valor, 'BRL', locale='pt_BR'))
                
                df_export = df_filtered[['upload_id', 'unidade', 'timestamp', 'usuario', 'rubrica', 'fornecedor', 'valor_total', 'arquivo']]
                df_export['valor_total'] = df_export['valor_total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
                
                col_export1, col_export2 = st.columns(2)
                with col_export1:
                    csv_buffer = BytesIO()
                    df_export.to_csv(csv_buffer, index=False, encoding='utf-8')
                    csv_buffer.seek(0)
                    st.download_button(
                        label="📊 Exportar Histórico como CSV",
                        data=csv_buffer,
                        file_name=f"historico_ocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                with col_export2:
                    excel_buffer = BytesIO()
                    df_export.to_excel(excel_buffer, index=False)
                    excel_buffer.seek(0)
                    st.download_button(
                        label="📈 Exportar Histórico como Excel",
                        data=excel_buffer,
                        file_name=f"historico_ocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )

                if st.button("📄 Exportar Histórico como PDF"):
                    buffer = BytesIO()
                    doc = SimpleDocTemplate(buffer, pagesize=A4)
                    flowables = []
                    styles = getSampleStyleSheet()

                    flowables.append(Paragraph("Histórico de Ordens de Compra", styles['Title']))
                    flowables.append(Spacer(1, 12))

                    for _, group in df_groups.iterrows():
                        flowables.append(Paragraph(f"Upload {group['timestamp']} ({group['unidade']}, {group['usuario']}, {group['num_ocs']} OCs)", styles['Heading2']))
                        df_group = df_filtered[df_filtered['upload_id'] == group['upload_id']]
                        data = [["Rubrica", "Fornecedor", "Valor Total"]]
                        for _, row in df_group.iterrows():
                            data.append([row['rubrica'], row['fornecedor'], format_currency(row['valor_total'], 'BRL', locale='pt_BR')])
                        table = Table(data)
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
                            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                        ]))
                        flowables.append(table)
                        flowables.append(Spacer(1, 12))

                    doc.build(flowables)
                    pdf_buffer = buffer.getvalue()
                    st.download_button(
                        label="Clique para Baixar PDF Consolidado",
                        data=pdf_buffer,
                        file_name=f"historico_ocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf"
                    )

                col_pag1, col_pag2, col_pag3 = st.columns([2, 1, 2])
                with col_pag2:
                    st.write(f"Página {st.session_state.pagina_historico} de {total_paginas}")
                col_pag1, col_pag2, col_pag3 = st.columns([1, 1, 1])
                with col_pag1:
                    if st.button("⬅️ Anterior", disabled=st.session_state.pagina_historico <= 1):
                        st.session_state.pagina_historico -= 1
                        st.rerun()
                with col_pag3:
                    if st.button("Próximo ➡️", disabled=st.session_state.pagina_historico >= total_paginas):
                        st.session_state.pagina_historico += 1
                        st.rerun()
                
                st.subheader("Uploads de Ordens de Compra")
                for _, group in df_groups_paginado.iterrows():
                    with st.expander(f"Upload {group['timestamp']} ({group['unidade']}, {group['usuario']}, {group['num_ocs']} OCs, {group['valor_total_fmt']})"):
                        df_fornecedores = df_filtered[df_filtered['upload_id'] == group['upload_id']].groupby('fornecedor').agg({
                            'valor_total': 'sum',
                            'rubrica': 'nunique',
                            'id': 'count'
                        }).reset_index()
                        df_fornecedores = df_fornecedores.rename(columns={'rubrica': 'num_rubricas', 'id': 'num_ocs'})
                        df_fornecedores['valor_total_fmt'] = df_fornecedores['valor_total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
                        
                        st.write("**Fornecedores**")
                        st.dataframe(
                            df_fornecedores[['fornecedor', 'num_rubricas', 'valor_total_fmt']],
                            column_config={
                                'fornecedor': "Fornecedor",
                                'num_rubricas': "Nº de Rubricas",
                                'valor_total_fmt': "Valor Total"
                            },
                            use_container_width=True
                        )
                        
                        for _, forn in df_fornecedores.iterrows():
                            st.markdown(f"**Rubricas para {forn['fornecedor']}**")
                            df_rubricas = df_filtered[(df_filtered['upload_id'] == group['upload_id']) & (df_filtered['fornecedor'] == forn['fornecedor'])]
                            df_rubricas['valor_total_fmt'] = df_rubricas['valor_total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
                            for _, oc in df_rubricas.iterrows():
                                cols = st.columns([3, 1, 1, 2] if (st.session_state.is_admin or perm_historico == "completo") else [3, 1, 1])
                                cols[0].write(f"Rubrica: {oc['rubrica']} ({format_currency(oc['valor_total'], 'BRL', locale='pt_BR')})")
                                if cols[1].button("📥 Baixar", key=f"download_{oc['id']}"):
                                    nome_arquivo, pdf_content = obter_pdf_oc(oc['id'])
                                    if pdf_content:
                                        st.download_button(
                                            label="Clique para Baixar PDF",
                                            data=pdf_content,
                                            file_name=nome_arquivo,
                                            mime="application/pdf",
                                            key=f"download_pdf_{oc['id']}"
                                        )
                                    else:
                                        st.warning(f"PDF não disponível para {oc['arquivo']} (OC antiga).")
                                if cols[2].button("ℹ️ Detalhes", key=f"detalhes_{oc['id']}"):
                                    itens = json.loads(oc['itens_json'])
                                    if itens:
                                        df_itens = pd.DataFrame(itens)
                                        df_itens['Valor Unitário'] = df_itens['Valor Unitário'].apply(
                                            lambda x: format_currency(float(x.replace('R$', '').replace('.', '').replace(',', '.')),
                                                                     'BRL', locale='pt_BR') if isinstance(x, str) else format_currency(x, 'BRL', locale='pt_BR'))
                                        df_itens['Total'] = df_itens['Total'].apply(
                                            lambda x: format_currency(float(x.replace('R$', '').replace('.', '').replace(',', '.')),
                                                                     'BRL', locale='pt_BR') if isinstance(x, str) else format_currency(x, 'BRL', locale='pt_BR'))
                                        st.dataframe(df_itens, use_container_width=True)
                                    else:
                                        st.info("Nenhum detalhe disponível para esta OC (OC antiga).")
                                if (st.session_state.is_admin or perm_historico == "completo") and len(cols) > 3:
                                    with cols[3]:
                                        with st.form(key=f"editar_form_{oc['id']}"):
                                            st.write("Editar OC:")
                                            nova_rubrica = st.text_input("Rubrica", value=oc['rubrica'], key=f"edit_rubrica_{oc['id']}")
                                            novo_fornecedor = st.text_input("Fornecedor", value=oc['fornecedor'], key=f"edit_fornecedor_{oc['id']}")
                                            submit_editar = st.form_submit_button("Salvar Alterações")
                                            if submit_editar:
                                                conn = sqlite3.connect("compras.db")
                                                cursor = conn.cursor()
                                                cursor.execute(
                                                    "UPDATE ordens_compra SET rubrica = ?, fornecedor = ? WHERE id = ?",
                                                    (nova_rubrica, novo_fornecedor, oc['id'])
                                                )
                                                conn.commit()
                                                conn.close()
                                                st.success(f"OC {oc['arquivo']} atualizada!")
                                                st.rerun()
                                        with st.form(key=f"excluir_form_{oc['id']}"):
                                            st.write("Deseja excluir esta OC?")
                                            submit_excluir = st.form_submit_button("Confirmar Exclusão")
                                            if submit_excluir:
                                                excluir_oc(oc['id'])
                                                st.success(f"OC {oc['arquivo']} excluída com sucesso!")
                                                st.rerun()
                            st.markdown("---")
        else:
            st.info("Nenhuma ordem de compra registrada.")

# Aba Minha Conta
if tab5:
    with tab5:
        st.header("🔑 Minha Conta")
        st.subheader("Alterar Minha Senha")
        with st.form("alterar_minha_senha_form"):
            senha_atual = st.text_input("Senha Atual:", type="password", key="senha_atual")
            nova_senha = st.text_input("Nova Senha:", type="password", key="nova_senha_minha_conta")
            confirmar_senha = st.text_input("Confirmar Nova Senha:", type="password", key="confirmar_senha_minha_conta")
            submit_alterar = st.form_submit_button("Alterar Senha")
            
            if submit_alterar:
                if not senha_atual or not nova_senha or not confirmar_senha:
                    st.error("Todos os campos são obrigatórios.")
                elif not verificar_senha_atual(st.session_state.usuario, senha_atual):
                    st.error("Senha atual incorreta.")
                elif nova_senha != confirmar_senha:
                    st.error("As novas senhas não coincidem.")
                elif len(nova_senha) < 6:
                    st.error("A nova senha deve ter pelo menos 6 caracteres.")
                else:
                    sucesso, mensagem = alterar_senha(st.session_state.usuario, nova_senha)
                    if sucesso:
                        st.success(mensagem)
                    else:
                        st.error(mensagem)

# Aba Registro de NFs
if tab_nfs:
    with tab_nfs:
        st.header("📋 Registro de Notas Fiscais")
        
        if perm_nfs in ["registrar", "completo"]:
            # Formulário para registrar nova NF
            st.subheader("Adicionar Nova NF")
            with st.form("registro_nf_form"):
                localizador = st.text_input("Localizador (ID) 1Doc", placeholder="Ex.: 4.855/2025")
                col1, col2 = st.columns(2)
                with col1:
                    data_emissao = st.date_input("Data de Emissão NF")
                with col2:
                    data_vencimento = st.date_input("Data de Vencimento NF")
                numero_nf = st.text_input("Número de Emissão NF", placeholder="Ex.: 13480")
                unidade = st.selectbox("Unidade Solicitante", list(UNIDADES.keys()))
                rubrica = st.selectbox("Rubrica", [
                    "Medicamentos", "Material Medico Descartavel", "Nutrição", "Expediente", "Outros"
                ])
                cnpj_fornecedor = st.text_input("CNPJ Fornecedor", placeholder="Ex.: 32.179.973/0001-26")
                fornecedor = st.text_input("Fornecedor", placeholder="Ex.: LONGEVITY PHARMA LTDA")
                valor_total = st.number_input("Valor Total NF (R$)", min_value=0.0, step=0.01)
                nf_assinada = st.selectbox("Nota Fiscal Assinada?", ["Sim", "Não"])
                observacoes = st.text_area("Observações", placeholder="Ex.: NF vencida, NF sem dados bancários")
                submit_nf = st.form_submit_button("Registrar NF")

                if submit_nf:
                    # Validações
                    if not localizador or not numero_nf or not cnpj_fornecedor or not fornecedor:
                        st.error("Os campos Localizador, Número NF, CNPJ Fornecedor e Fornecedor são obrigatórios.")
                    elif data_vencimento < data_emissao:
                        st.error("Data de vencimento não pode ser anterior à data de emissão.")
                    else:
                        # Formatar datas como string (ISO)
                        data_emissao_str = data_emissao.isoformat()
                        data_vencimento_str = data_vencimento.isoformat()
                        # Registrar NF
                        registrar_nf(
                            st.session_state.usuario,
                            localizador,
                            data_emissao_str,
                            data_vencimento_str,
                            numero_nf,
                            unidade,
                            rubrica,
                            cnpj_fornecedor,
                            fornecedor,
                            valor_total,
                            nf_assinada,
                            observacoes
                        )
                        st.success(f"Nota Fiscal {localizador} registrada com sucesso!")
                        st.rerun()
        else:
            st.info("Você tem permissão apenas para visualizar as notas fiscais registradas.")

        # Exibir NFs registradas
        st.subheader("Notas Fiscais Registradas")
        df_nfs = carregar_nfs_usuario(st.session_state.usuario)
        if df_nfs.empty:
            st.info("Nenhuma nota fiscal registrada.")
        else:
            # Formatando valores para exibição
            df_nfs['valor_total_fmt'] = df_nfs['valor_total'].apply(lambda x: format_currency(x, 'BRL', locale='pt_BR'))
            df_nfs['timestamp'] = pd.to_datetime(df_nfs['timestamp']).dt.strftime('%d/%m/%Y %H:%M')
            df_nfs['data_emissao'] = pd.to_datetime(df_nfs['data_emissao']).dt.strftime('%d/%m/%Y')
            df_nfs['data_vencimento'] = pd.to_datetime(df_nfs['data_vencimento']).dt.strftime('%d/%m/%Y')

            for _, nf in df_nfs.iterrows():
                with st.expander(f"NF {nf['localizador']} - {nf['unidade']} ({nf['valor_total_fmt']})"):
                    cols = st.columns([3, 1] if perm_nfs != "completo" else [3, 1])
                    cols[0].write(f"**Data Registro**: {nf['timestamp']}")
                    cols[0].write(f"**Data Emissão**: {nf['data_emissao']}")
                    cols[0].write(f"**Data Vencimento**: {nf['data_vencimento']}")
                    cols[0].write(f"**Número NF**: {nf['numero_nf']}")
                    cols[0].write(f"**Rubrica**: {nf['rubrica']}")
                    cols[0].write(f"**CNPJ Fornecedor**: {nf['cnpj_fornecedor']}")
                    cols[0].write(f"**Fornecedor**: {nf['fornecedor']}")
                    cols[0].write(f"**NF Assinada**: {nf['nf_assinada']}")
                    cols[0].write(f"**Observações**: {nf['observacoes'] or 'Nenhuma'}")

                    # Botões de edição e exclusão (apenas para completo)
                    if perm_nfs == "completo":
                        with cols[1]:
                            with st.form(key=f"editar_nf_{nf['id']}"):
                                st.write("Editar NF:")
                                novo_localizador = st.text_input("Localizador", value=nf['localizador'], key=f"edit_localizador_{nf['id']}")
                                nova_data_emissao = st.date_input("Data Emissão", value=pd.to_datetime(nf['data_emissao']), key=f"edit_data_emissao_{nf['id']}")
                                nova_data_vencimento = st.date_input("Data Vencimento", value=pd.to_datetime(nf['data_vencimento']), key=f"edit_data_vencimento_{nf['id']}")
                                novo_numero_nf = st.text_input("Número NF", value=nf['numero_nf'], key=f"edit_numero_nf_{nf['id']}")
                                nova_unidade = st.selectbox("Unidade", list(UNIDADES.keys()), index=list(UNIDADES.keys()).index(nf['unidade']), key=f"edit_unidade_{nf['id']}")
                                nova_rubrica = st.selectbox("Rubrica", ["Medicamentos", "Material Medico Descartavel", "Nutrição", "Expediente", "Outros"], index=["Medicamentos", "Material Medico Descartavel", "Nutrição", "Expediente", "Outros"].index(nf['rubrica']) if nf['rubrica'] in ["Medicamentos", "Material Medico Descartavel", "Nutrição", "Expediente", "Outros"] else 4, key=f"edit_rubrica_{nf['id']}")
                                novo_cnpj = st.text_input("CNPJ Fornecedor", value=nf['cnpj_fornecedor'], key=f"edit_cnpj_{nf['id']}")
                                novo_fornecedor = st.text_input("Fornecedor", value=nf['fornecedor'], key=f"edit_fornecedor_{nf['id']}")
                                novo_valor = st.number_input("Valor Total (R$)", value=float(nf['valor_total']), min_value=0.0, step=0.01, key=f"edit_valor_{nf['id']}")
                                nova_nf_assinada = st.selectbox("NF Assinada?", ["Sim", "Não"], index=0 if nf['nf_assinada'] == "Sim" else 1, key=f"edit_nf_assinada_{nf['id']}")
                                novas_observacoes = st.text_area("Observações", value=nf['observacoes'] or "", key=f"edit_observacoes_{nf['id']}")
                                submit_editar = st.form_submit_button("Salvar Alterações")
                                if submit_editar:
                                    if not novo_localizador or not novo_numero_nf or not novo_cnpj or not novo_fornecedor:
                                        st.error("Campos obrigatórios não preenchidos.")
                                    elif nova_data_vencimento < nova_data_emissao:
                                        st.error("Data de vencimento não pode ser anterior à data de emissão.")
                                    else:
                                        atualizar_nf(
                                            nf['id'],
                                            novo_localizador,
                                            nova_data_emissao.isoformat(),
                                            nova_data_vencimento.isoformat(),
                                            novo_numero_nf,
                                            nova_unidade,
                                            nova_rubrica,
                                            novo_cnpj,
                                            novo_fornecedor,
                                            novo_valor,
                                            nova_nf_assinada,
                                            novas_observacoes
                                        )
                                        st.success(f"NF {novo_localizador} atualizada!")
                                        st.rerun()

                            with st.form(key=f"excluir_nf_{nf['id']}"):
                                st.write("Excluir NF?")
                                submit_excluir = st.form_submit_button("Confirmar Exclusão")
                                if submit_excluir:
                                    excluir_nf(nf['id'])
                                    st.success(f"NF {nf['localizador']} excluída!")
                                    st.rerun()

# Aba Administração de Usuários
if tab_admin and st.session_state.is_admin:
    with tab_admin:
        st.header("🔧 Administração de Usuários")
        
        # Cadastrar novo usuário
        st.subheader("Cadastrar Novo Usuário")
        with st.form("cadastro_usuario_form"):
            novo_usuario = st.text_input("Novo Usuário:", key="novo_usuario")
            nova_senha = st.text_input("Senha:", type="password", key="nova_senha")
            confirmar_nova_senha = st.text_input("Confirmar Senha:", type="password", key="confirmar_nova_senha")
            submit_cadastro = st.form_submit_button("Cadastrar Usuário")
            
            if submit_cadastro:
                if not novo_usuario or not nova_senha or not confirmar_nova_senha:
                    st.error("Todos os campos são obrigatórios.")
                elif nova_senha != confirmar_nova_senha:
                    st.error("As senhas não coincidem.")
                elif len(nova_senha) < 6:
                    st.error("A senha deve ter pelo menos 6 caracteres.")
                else:
                    sucesso, mensagem = cadastrar_usuario(novo_usuario, nova_senha)
                    if sucesso:
                        # Dar permissões padrão ao novo usuário
                        permissoes_padrao = {
                            "Gerar OCs": {"nivel": "completo"},
                            "Painel de Gastos": {"nivel": "presente"},
                            "Controle de Saldo": {"nivel": "presente"},
                            "Histórico de OCs": {"nivel": "visualizar"},
                            "Minha Conta": {"nivel": "presente"}
                        }
                        atualizar_permissoes_usuario(novo_usuario, permissoes_padrao, st.session_state.usuario)
                        st.success(mensagem)
                    else:
                        st.error(mensagem)

        # Gerenciar permissões de abas
        st.subheader("Gerenciar Permissões de Abas")
        usuarios = listar_usuarios(excluir_self=st.session_state.usuario)
        if usuarios:
            usuario_selecionado = st.selectbox("Selecione o Usuário:", usuarios, key="usuario_permissoes")
            permissoes_atuais = get_permissoes_usuario(usuario_selecionado)
            
            # Confirmação Visual
            st.write("**Permissões Atuais do Usuário**")
            permissoes_df = pd.DataFrame([
                {"Aba": aba, "Nível de Acesso": permissoes_atuais.get(aba, {"nivel": "sem_acesso"})["nivel"].replace("_", " ").capitalize()}
                for aba in todas_abas
                if permissoes_atuais.get(aba, {"nivel": "sem_acesso"})["nivel"] != "sem_acesso"
            ])
            if permissoes_df.empty:
                st.info("Nenhuma permissão definida para este usuário.")
            else:
                st.dataframe(
                    permissoes_df,
                    column_config={"Aba": "Aba", "Nível de Acesso": "Nível de Acesso"},
                    use_container_width=True
                )

            with st.form(f"permissoes_form_{usuario_selecionado}"):
                st.write("Definir Permissões:")
                novas_permissoes = {}
                for aba, niveis in todas_abas.items():
                    if aba == "Administração de Usuários" and usuario_selecionado != st.session_state.usuario:
                        continue  # Apenas admins podem ter esta aba
                    label = {
                        "sem_acesso": "Sem Acesso",
                        "visualizar": "Visualizar",
                        "registrar": "Registrar (NFs)",
                        "completo": "Completo",
                        "presente": "Acesso"
                    }
                    nivel_atual = permissoes_atuais.get(aba, {"nivel": "sem_acesso"})["nivel"]
                    opcoes = [label[n] for n in niveis]
                    index = niveis.index(nivel_atual) if nivel_atual in niveis else 0
                    nivel_selecionado = st.selectbox(
                        f"Nível de acesso para {aba}:",
                        opcoes,
                        index=index,
                        key=f"perm_{usuario_selecionado}_{aba}"
                    )
                    nivel_key = [k for k, v in label.items() if v == nivel_selecionado][0]
                    novas_permissoes[aba] = {"nivel": nivel_key}
                
                submit_permissoes = st.form_submit_button("Salvar Permissões")
                
                if submit_permissoes:
                    atualizar_permissoes_usuario(usuario_selecionado, novas_permissoes, st.session_state.usuario)
                    st.success(f"Permissões atualizadas para {usuario_selecionado}!")
                    st.rerun()
        else:
            st.info("Nenhum outro usuário disponível para gerenciar permissões.")

        # Excluir usuário
        st.subheader("Excluir Usuário")
        if usuarios:
            with st.form("excluir_usuario_form"):
                usuario_excluir = st.selectbox("Selecione o usuário para excluir:", usuarios, key="usuario_excluir")
                submit_xcluir = st.form_submit_button("Confirmar Exclusão")
                
                if submit_xcluir:
                    excluir_usuario(usuario_excluir)
                    st.success(f"Usuário {usuario_excluir} excluído com sucesso!")
                    st.rerun()
        else:
            st.info("Nenhum outro usuário disponível para exclusão.")

        # Log de alterações
        st.subheader("Log de Alterações de Permissões")
        df_log = carregar_log_permissoes()
        if df_log.empty:
            st.info("Nenhum registro de alterações.")
        else:
            df_log['timestamp'] = pd.to_datetime(df_log['timestamp']).dt.strftime('%d/%m/%Y %H:%M:%S')
            st.dataframe(
                df_log[['timestamp', 'admin_username', 'target_username', 'acao']],
                column_config={
                    "timestamp": "Data/Hora",
                    "admin_username": "Administrador",
                    "target_username": "Usuário Alvo",
                    "acao": "Ação"
                },
                use_container_width=True
            )
