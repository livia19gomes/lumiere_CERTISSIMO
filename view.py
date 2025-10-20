from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime, timedelta
from main import app, con
import jwt

app = Flask(__name__)
CORS(app, origins=["*"])

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id, email):
    payload = {'id_usuario': user_id, 'email':email}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token

def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

def verificar_adm(id_cadastro):
    cur = con.cursor()
    cur.execute("SELECT tipo FROM cadastro WHERE id_cadastro = ?", (id_cadastro,))
    tipo = cur.fetchone()

    if tipo and tipo[0] == 'adm':
        return True
    else:
        return False

@app.route('/cadastro', methods=['POST'])
def cadastro_usuario():
    if not request.is_json:
        return jsonify({"error": "É necessário enviar JSON válido"}), 400

    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON vazio"}), 400

    # campos básicos obrigatórios (tipo NÃO está aqui)
    campos_basicos = ['nome', 'email', 'telefone', 'senha']
    faltando = [campo for campo in campos_basicos if not data.get(campo)]
    if faltando:
        return jsonify({"error": f"Campos obrigatórios faltando: {', '.join(faltando)}"}), 400

    nome = data['nome']
    email = data['email']
    telefone = data['telefone']
    senha = data['senha']
    tipo = data.get('tipo', 'usuario').lower()   # se não vier, assume "usuario"
    categoria = data.get('categoria')

    if tipo == 'profissional' and not categoria:
        return jsonify({"error": "Campo 'categoria' é obrigatório para profissionais"}), 400

    # se for adm ou usuario, categoria não é necessária
    if tipo in ['adm', 'usuario']:
        categoria = None

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({"error": "Este usuário já foi cadastrado!"}), 400

    senha_hashed = generate_password_hash(senha)

    cur.execute(
        "INSERT INTO CADASTRO (NOME, EMAIL, TELEFONE, SENHA, CATEGORIA, TIPO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (nome, email, telefone, senha_hashed, categoria, tipo, True)
    )
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email,
            'tipo': tipo,
            'categoria': categoria
        }
    }), 200

@app.route('/cadastro', methods=['GET'])
def listar_usuarios():
    try:
        cur = con.cursor()

        # Parâmetro opcional: ?tipo=profissional
        tipo = request.args.get('tipo')

        if tipo:
            cur.execute("""
                SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                FROM CADASTRO 
                WHERE tipo = ?
            """, (tipo,))
        else:
            cur.execute("""
                SELECT id_cadastro, nome, email, telefone, tipo, categoria, ativo 
                FROM CADASTRO
            """)

        rows = cur.fetchall()
        cur.close()

        if not rows:
            return jsonify({"message": "Nenhum usuário encontrado"}), 404

        usuarios = []
        for row in rows:
            usuarios.append({
                "id": row[0],
                "nome": row[1],
                "email": row[2],
                "telefone": row[3],
                "tipo": row[4],
                "categoria": row[5],
                "ativo": bool(row[6])
            })

        return jsonify(usuarios), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_Usuario(id):
    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE id_cadastro = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    cur.execute("DELETE FROM cadastro WHERE id_cadastro = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuario excluído com sucesso!",
        'id_cadastro': id
    })

@app.route('/cadastro/<int:id>', methods=['PUT'])
def editar_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM CADASTRO WHERE id_cadastro = ?", (id,))
    usuarios_data = cur.fetchone()

    if not usuarios_data:
        cur.close()
        return jsonify({"error": "Usuário não foi encontrado"}), 404

    email_armazenado = usuarios_data[2]
    tipo_armazenado = usuarios_data[6]
    ativo_armazenado = usuarios_data[7]

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    categoria = data.get('categoria')
    tipo = data.get('tipo')
    ativo = data.get('ativo')

    # validação de senha
    if senha is not None:
        senha_check = validar_senha(senha)
        if senha_check is not True:
            return senha_check
        senha = generate_password_hash(senha)
    else:
        senha = usuarios_data[4]  # mantém a senha antiga

    if tipo is None:
        tipo = tipo_armazenado
    if ativo is None:
        ativo = ativo_armazenado

    if email_armazenado != email:
        cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({"message": "Este usuário já foi cadastrado!"}), 400

    cur.execute(
        "UPDATE cadastro SET nome = ?, email = ?, telefone = ?, senha = ?, categoria = ?, tipo = ?, ativo = ? WHERE id_cadastro = ?",
        (nome, email, telefone, senha, categoria, tipo, ativo, id)
    )

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'categoria': categoria,
            'tipo': tipo,
            'ativo': ativo
        }
    })

tentativas = {}
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    print(email, senha)

    if not email or not senha:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    cur = con.cursor()
    cur.execute("SELECT senha, tipo, id_cadastro, ativo, nome, telefone FROM CADASTRO WHERE email = ?", (email,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario:
        return jsonify({"error": "Usuário ou senha inválidos"}), 401

    senha_armazenada, tipo, id_cadastro, ativo, nome, telefone = usuario

    if not ativo:
        return jsonify({"error": "Usuário inativo"}), 401

    if check_password_hash(senha_armazenada, senha):
        # Login OK, gera token
        token = generate_token(id_cadastro, email)
        return jsonify({
            "message": "Login realizado com sucesso!",
            "usuario": {
                "id_cadastro": id_cadastro,
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "tipo": tipo,
                "token": token
            }
        })

    else:
        # Controle de tentativas
        if id_cadastro not in tentativas:
            tentativas[id_cadastro] = 0

        if tipo != 'adm':  # Se o usuário não for 'adm', contar as tentativas
            tentativas[id_cadastro] += 1
            if tentativas[id_cadastro] >= 3:
                cur = con.cursor()
                cur.execute("UPDATE CADASTRO SET ATIVO = false WHERE id_cadastro = ?", (id_cadastro,))
                con.commit()
                cur.close()
                return jsonify({"error": "Usuário inativado por excesso de tentativas."}), 403

        return jsonify({"error": "Senha incorreta"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Token de autenticação necessário"}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        return jsonify({"message": "Logout realizado com sucesso!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

codigos_temp = {}

@app.route('/servico', methods=['POST'])
def cadastrar_servico():
    try:
        data = request.get_json()
        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao_horas = data.get('duracao_horas')

        # Verifica se todos os campos obrigatórios foram informados
        if not descricao or not valor or not duracao_horas:
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        # Verifica se o formato de duracao_horas é válido
        try:
            # Valida o formato "HH:MM" para a duração
            horas, minutos = map(int, duracao_horas.split(":"))
            if horas < 0 or minutos < 0 or minutos >= 60:
                raise ValueError("Formato inválido de duração (deve ser HH:MM).")
        except ValueError as e:
            return jsonify({"error": f"Erro no formato de DURACAO_HORAS: {str(e)}"}), 400

        # Conecta ao banco de dados
        cur = con.cursor()

        # Verifica se o serviço já existe
        cur.execute("SELECT COUNT(*) FROM SERVICO WHERE DESCRICAO = ?", (descricao,))
        if cur.fetchone()[0] > 0:
            return jsonify({"error": "Este serviço já está cadastrado"}), 400

        # Converte para o formato "HH:MM:SS" (garante que é uma string para TIME)
        duracao_horas = f"{horas:02}:{minutos:02}:00"

        # Insere o novo serviço
        cur.execute("""
            INSERT INTO SERVICO (DESCRICAO, VALOR, DURACAO_HORAS)
            VALUES (?, ?, ?)
        """, (descricao, valor, duracao_horas))

        # Confirma a transação
        con.commit()
        return jsonify({"message": "Serviço cadastrado com sucesso!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servico', methods=['GET'])
def listar_servicos():
    try:
        cur = con.cursor()

        cur.execute("SELECT ID_SERVICO, DESCRICAO, VALOR, DURACAO_HORAS FROM SERVICO")
        servicos = cur.fetchall()

        cur.close()

        lista = []
        for s in servicos:
            duracao = s[3]
            if duracao is not None:
                duracao_horas = duracao.hour + duracao.minute / 60 + duracao.second / 3600
            else:
                duracao_horas = None

            lista.append({
                "id_servico": s[0],
                "descricao": s[1],
                "valor": float(s[2]) if s[2] is not None else 0.0,
                "duracao_horas": duracao_horas
            })

        return jsonify(lista), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servico/<int:id_servico>', methods=['PUT'])
def editar_servico(id_servico):
    try:
        data = request.get_json()

        descricao = data.get('descricao')
        valor = data.get('valor')
        duracao = data.get('duracao_horas')

        if not descricao and valor is None and duracao is None:
            return jsonify({"error": "Pelo menos um campo deve ser informado para atualizar"}), 400

        cur = con.cursor()

        cur.execute("SELECT COUNT(*) FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        if cur.fetchone()[0] == 0:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 404

        if descricao:
            cur.execute("UPDATE SERVICO SET DESCRICAO = ? WHERE ID_SERVICO = ?", (descricao, id_servico))
        if valor is not None:
            cur.execute("UPDATE SERVICO SET VALOR = ? WHERE ID_SERVICO = ?", (valor, id_servico))
        if duracao is not None:
            cur.execute("UPDATE SERVICO SET DURACAO_HORAS = ? WHERE ID_SERVICO = ?", (duracao, id_servico))

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço atualizado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/agenda', methods=['POST'])
def cadastrar_agendamento():
    try:
        data = request.get_json()

        id_profissional = data.get('id_profissional')
        id_servico = data.get('id_servico')
        data_hora_str = data.get('data_hora')  # Ex.: "2025-10-07 14:30:00"

        if not id_profissional or not id_servico or not data_hora_str:
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        from datetime import datetime, timedelta

        data_hora = datetime.strptime(data_hora_str, "%Y-%m-%d %H:%M:%S")

        cur = con.cursor()

        # Busca duração do serviço
        cur.execute("SELECT DURACAO_HORAS FROM SERVICO WHERE ID_SERVICO = ?", (id_servico,))
        result = cur.fetchone()

        # Verifica se o serviço existe e se tem duração válida
        if not result:
            cur.close()
            return jsonify({"error": "Serviço não encontrado"}), 400
        if result[0] is None:
            cur.close()
            return jsonify({"error": "Serviço sem duração cadastrada"}), 400

        duracao = float(result[0])  # duração em horas
        fim_novo_agendamento = data_hora + timedelta(hours=duracao)

        # Busca agendamentos do mesmo profissional
        cur.execute("""
            SELECT A.DATA_HORA, S.DURACAO_HORAS
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            WHERE A.ID_PROFISSIONAL = ?
        """, (id_profissional,))

        agendamentos = cur.fetchall()

        # Verifica conflitos
        for ag in agendamentos:
            inicio_existente = ag[0]
            duracao_existente = ag[1]

            # Se algum agendamento tiver duração nula, ignora esse registro
            if duracao_existente is None:
                continue

            duracao_existente = float(duracao_existente)
            fim_existente = inicio_existente + timedelta(hours=duracao_existente)

            # Se houver qualquer sobreposição
            if (data_hora < fim_existente) and (fim_novo_agendamento > inicio_existente):
                cur.close()
                return jsonify({"error": "O horário conflita com outro agendamento do profissional"}), 400

        # Insere o novo agendamento
        cur.execute("""
            INSERT INTO AGENDA (ID_PROFISSIONAL, ID_SERVICO, DATA_HORA)
            VALUES (?, ?, ?)
        """, (id_profissional, id_servico, data_hora))
        con.commit()
        cur.close()

        return jsonify({"message": "Agendamento cadastrado com sucesso!"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/agenda', methods=['GET'])
def listar_agendamentos():
    try:
        cur = con.cursor()

        cur.execute("""
            SELECT 
                A.ID_AGENDA,
                A.ID_PROFISSIONAL,
                S.DESCRICAO AS SERVICO,
                A.DATA_HORA,
                S.DURACAO_HORAS
            FROM AGENDA A
            JOIN SERVICO S ON A.ID_SERVICO = S.ID_SERVICO
            ORDER BY A.DATA_HORA
        """)

        agendamentos = cur.fetchall()
        cur.close()

        if not agendamentos:
            return jsonify({"message": "Nenhum agendamento encontrado"}), 200

        # Formata o resultado em lista de dicionários
        agendamentos_formatados = []
        for ag in agendamentos:
            agendamentos_formatados.append({
                "id_agenda": ag[0],
                "id_profissional": ag[1],
                "servico": ag[2],
                "data_hora": ag[3].strftime("%Y-%m-%d %H:%M:%S") if ag[3] else None,
                "duracao_horas": float(ag[4]) if ag[4] is not None else None
            })

        return jsonify(agendamentos_formatados), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



