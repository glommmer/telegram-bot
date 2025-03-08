import os
import random
import base64
import logging
import asyncio
import cx_Oracle
import configparser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from quart import Quart, request
from utils.redis_custom_module import RedisConversationHandler, RedisActions
from telegram import Update, BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackContext,
    MessageHandler,
    filters,
    ConversationHandler,
    CallbackQueryHandler,
)


# Read configuration file
current_dir = os.path.dirname(os.path.abspath(__file__))
ini_path = os.path.join(current_dir, "env/telegram_bot.cfg")
config = configparser.ConfigParser()
config.read(ini_path)

# Load environment variables
DSN = config["ORACLE"]["DSN"]
ORA_USER = config["ORACLE"]["USER"]
ORA_PASS = config["ORACLE"]["PASSWORD"]
AES_KEY = config["AES"]["KEY"]
AES_IV = config["AES"]["IV"]
BOT_ID = config["BOT"]["ID"]
STICKER = config["STICKER"]




def connect_to_oracle(user: str, password: str, sid: str):
    connection = cx_Oracle.connect(user=user, password=password, dsn=sid)
    return connection


def create_cursor(connection: cx_Oracle.Connection):
    cursor = connection.cursor()
    return cursor


def aes_decrypt(ciphertext: str, key: str, iv: str) -> str:
    logger.info(f"## aes_decrypt")
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    ciphertext_bytes = base64.b64decode(ciphertext)
    cipher = Cipher(
        algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode("utf-8")


def get_bot_credentials(bot_id):
    logger.info(f"## get_bot_credentials: {bot_id}")
    c = create_cursor(connect_to_oracle(ORA_USER, ORA_PASS, DSN))
    c.execute(
        "SELECT token, password, root_url FROM telegram.bot_credentials WHERE id = :id",
        {"id": bot_id},  # 봇 ID
    )
    row = c.fetchone()
    if row:
        encrypted_token = row[0]
        encrypted_password = row[1]
        route = row[2]
        decrypted_token = aes_decrypt(encrypted_token, AES_KEY, AES_IV)
        decrypted_password = aes_decrypt(encrypted_password, AES_KEY, AES_IV)
        return decrypted_token, decrypted_password, route
    else:
        logger.info("No data found for the given ID.")


def get_allowed_users():
    logger.info(f"## get_allowed_users")
    c = create_cursor(connect_to_oracle(ORA_USER, ORA_PASS, DSN))
    c.execute("SELECT user_id FROM telegram.allowed_users")
    return {row[0] for row in c.fetchall()}


def add_allowed_user(user_id, username, first_name, last_name, language_code, is_bot):
    logger.info(f"## add_allowed_user: {user_id}")
    conn = connect_to_oracle(ORA_USER, ORA_PASS, DSN)
    c = create_cursor(conn)
    c.execute(
        """
        INSERT INTO telegram.allowed_users (user_id, username, first_name, last_name, language_code, is_bot)
        VALUES (:user_id, :username, :first_name, :last_name, :language_code, :is_bot)
    """,
        {
            "user_id": user_id,
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "language_code": language_code,
            "is_bot": is_bot,
        },
    )
    conn.commit()
    RedisActions.add_user_to_redis(user_id)


# Retrieve bot credential information
TOKEN, PASSWORD, ROUTE = get_bot_credentials(BOT_ID)

# Conversation states
(
    START_DRAW,
    START_AUTH,
    SELECT_COUNT,
    INPUT_COUNT,
    SELECT_NAMING,
    INPUT_NAMES,
    WAITING_FOR_PASSWORD,
    SELECT_ABOUT,
    ABOUT_CAREER,
) = range(9)

# Initialize Application
app = Quart(__name__)  # Flask-like Quart Web Application
application = Application.builder().token(TOKEN).build()
RedisActions.sync_users_to_redis(get_allowed_users())


@app.route(ROUTE, methods=["POST"])
async def webhook():
    logger.info(f"## webhook()")
    update = Update.de_json(await request.get_json(), application.bot)
    await application.process_update(update)
    logger.debug(f"## update: {update}")
    return "OK"


async def start(update: Update, context: CallbackContext):
    logger.info(f"## start()")
    await context.bot.send_sticker(
        chat_id=update.effective_chat.id,
        sticker=STICKER["HELLO"],
    )
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text="언니, 안녕!\n/auth 인증은 했어?",
    )
    logger.debug(f"## update: {update} \n ## context: {context}")


async def auth_start(update, context):
    logger.info(f"## auth_start()")
    keyboard = [
        [InlineKeyboardButton("취소", callback_data="cancel")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    logger.debug(f"## Keyboard created: {keyboard}")
    user = update.effective_user
    if RedisActions.is_user_allowed_in_redis(user.id):
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["PASS"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="이제 인증 안해도 돼!",
        )
        logger.debug(f"## update: {update} \n ## context: {context}")
        return ConversationHandler.END
    else:
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["AUTH"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="비밀번호를 대라",
            reply_markup=reply_markup,
        )
        logger.debug(f"## update: {update} \n ## context: {context}")
        return WAITING_FOR_PASSWORD


async def auth_password(update, context):
    logger.info(f"## auth_password()")
    user = update.effective_user
    password = update.message.text
    if password == PASSWORD:
        if not RedisActions.is_user_allowed_in_redis(user.id):
            add_allowed_user(
                user_id=user.id,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name,
                language_code=user.language_code,
                is_bot=1 if user.is_bot else 0,
            )
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["OK"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="인증 완료!",
        )
        logger.debug(f"## update: {update} \n ## context: {context}")
        return ConversationHandler.END
    else:
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["WRONG"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="비밀번호 이거 아닌데?",
        )
        logger.debug(f"## update: {update} \n ## context: {context}")
        return await auth_start(update, context)


async def cancel(update, context):
    logger.info(f"## cancel()")
    await context.bot.send_sticker(
        chat_id=update.effective_chat.id,
        sticker=STICKER["BYE"],
    )
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text="잘가~!",
    )
    logger.debug(f"## update: {update} \n ## context: {context}")
    return ConversationHandler.END


def authorized_only(func):
    async def wrapper(update, context):
        user = update.effective_user
        if RedisActions.is_user_allowed_in_redis(user.id):
            return await func(update, context)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="언니, /auth 인증부터!",
            )

    return wrapper


@authorized_only
async def utils(update: Update, context: CallbackContext):
    logger.info(f"## utils()")
    keyboard = [
        [
            InlineKeyboardButton(  # InlineKeyboardButton: 인라인 버튼 정의
                text="\U0001F3B2제비뽑기",  # text : "뽑기"는 버튼에 표시될 텍스트
                callback_data="utils_drawing_lots",  # callback_Data : 사용자가 버튼을 클릭할 때 보내지는 데이터
            )
        ],
    ]  # 인라인 버튼 배열 정의
    logger.debug(f"## Keyboard created: {keyboard}")
    reply_markup = InlineKeyboardMarkup(keyboard)  # InlineKeyboardMarkup 객체 생성
    try:
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["PLAY"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="뭐하고 놀까!",
            reply_markup=reply_markup,  # 메시지 전송과 함께 인라인 키보드 표시
        )
        logger.info(f"## Message sent to chat ID: {update.effective_chat.id}")
    except Exception as e:
        logger.error(f"## Failed to send message: {e}")
    finally:
        logger.debug(f"## update: {update} \n ## context: {context}")


async def utils_button(update: Update, context):
    logger.info(f"## utils_button()")
    # 사용자 버튼 클릭 → callback_query 객체에 클릭 관련 정보 저장
    query = update.callback_query  # 클릭된 버튼에 대한 정보를 담고 있는 객체
    logger.info(f"## Button clicked. Callback data: {query.data}")
    try:
        # answer(): 버튼 클릭 이벤트에 대한 응답 송신
        # 클릭한 버튼이 유효하게 처리되었음을 Telegram 서버에 알려줌
        await query.answer()
        logger.info("## Callback query answered successfully.")
    except Exception as e:
        logger.error(f"## Error in answering callback query: {e}")
    finally:
        logger.debug(f"## update: {update} \n ## context: {context}")
    # Branching based on button selection
    if query.data == "utils_drawing_lots":
        return await select_count(update, context)


async def select_count(update: Update, context: CallbackContext):
    logger.info(f"## select_count()")
    query = update.callback_query
    await query.answer()
    keyboard = [
        [
            InlineKeyboardButton("2", callback_data="2"),
            InlineKeyboardButton("3", callback_data="3"),
            InlineKeyboardButton("4", callback_data="4"),
        ],
        [
            InlineKeyboardButton("5", callback_data="5"),
            InlineKeyboardButton("6", callback_data="6"),
            InlineKeyboardButton("더 많이", callback_data="other"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(
        text="몇 개 중에서 뽑아?",
        reply_markup=reply_markup,
    )
    logger.debug(f"## update: {update} \n ## context: {context}")
    return SELECT_COUNT


async def input_count(update: Update, context: CallbackContext):
    logger.info(f"## input_count()")
    user = update.effective_user
    query = update.callback_query
    await query.answer()
    if query.data == "other":
        await query.edit_message_text(text="얼마나 많이!?")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return INPUT_COUNT
    else:
        count = int(query.data)
        RedisActions.set_to_redis(user.id, "count", count)
        await query.edit_message_text(text=f"뽑기 개수: {count}")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return await select_naming(update, context)


async def save_count(update: Update, context: CallbackContext):
    logger.info(f"## save_count()")
    user = update.effective_user
    count = int(update.message.text)
    RedisActions.set_to_redis(user.id, "count", count)
    await update.message.reply_text(text=f"뽑기 개수: {count}")
    logger.debug(f"## update: {update} \n ## context: {context}")
    return await select_naming(update, context)


async def select_naming(update: Update, context: CallbackContext):
    logger.info(f"## select_naming()")
    keyboard = [
        [
            InlineKeyboardButton("응~ 그러자", callback_data="yes"),
            InlineKeyboardButton("아니, 그냥 하자", callback_data="no"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    query = update.callback_query
    if query:
        await query.edit_message_text(
            text="뽑기 이름 정할거야?",
            reply_markup=reply_markup,
        )
    else:
        await update.message.reply_text(
            text="뽑기 이름 정할거야?",
            reply_markup=reply_markup,
        )
    logger.debug(f"## update: {update} \n ## context: {context}")
    return SELECT_NAMING


async def set_names(update: Update, context: CallbackContext):
    logger.info(f"## set_names()")
    user = update.effective_user
    query = update.callback_query
    await query.answer()
    if query.data == "no":
        count = int(RedisActions.get_from_redis(user.id, "count"))
        names = [str(i + 1) for i in range(count)]
        RedisActions.set_list_to_redis(user.id, "names", *names)
        await query.edit_message_text(text=f"마루가 이 중에서 뽑을게!: {names}")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return await draw_result(update, context)
    else:
        await query.edit_message_text(text="뽑기 1 은 뭐라고 할거야?")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return INPUT_NAMES


async def save_names(update: Update, context: CallbackContext):
    logger.info(f"## save_names()")
    user = update.effective_user
    count = int(RedisActions.get_from_redis(user.id, "count"))
    logger.info(f"## count: {count}")
    # Add the user's input to the Redis list
    RedisActions.append_to_redis(user.id, "names", update.message.text)
    names = RedisActions.get_list_from_redis(user.id, "names")
    if len(names) < count:
        logger.info(f"## [{len(names)}/{count}]")
        await update.message.reply_text(text=f"뽑기 {len(names) + 1} 는(은)?")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return INPUT_NAMES
    else:
        logger.info(f"## [{len(names)}/{count}]")
        await update.message.reply_text(text=f"마루가 뽑을게!: {names}")
        logger.debug(f"## update: {update} \n ## context: {context}")
        return await draw_result(update, context)


async def draw_result(update: Update, context: CallbackContext):
    logger.info(f"## draw_result()")
    user = update.effective_user
    names = RedisActions.get_list_from_redis(user.id, "names")
    result = random.choice(names)
    await context.bot.send_sticker(
        chat_id=update.effective_chat.id,
        sticker=STICKER["RESULT"],
    )
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"≫ {result} 나왔어!!",
    )
    RedisActions.delete_from_redis(user.id, "count")
    RedisActions.delete_from_redis(user.id, "names")
    logger.debug(f"## update: {update} \n ## context: {context}")
    return ConversationHandler.END


def about_initial_keyboard():
    return [
        [InlineKeyboardButton("\U0001F4BCCareer", callback_data="career")],
        [InlineKeyboardButton("Cancel", callback_data="cancel")],
    ]


def go_back_keyboard():
    return [[InlineKeyboardButton("≪ 뒤로가기", callback_data="go_back")]]


@authorized_only
async def about(update: Update, context: CallbackContext):
    logger.info(f"## about()")
    keyboard = about_initial_keyboard()
    reply_markup = InlineKeyboardMarkup(keyboard)
    logger.debug(f"## Keyboard created: {keyboard}")
    try:
        await context.bot.send_sticker(
            chat_id=update.effective_chat.id,
            sticker=STICKER["QUESTION"],
        )
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="어떤 게 알고 싶어?",
            reply_markup=reply_markup,
        )
        logger.info(f"## Message sent to chat ID: {update.effective_chat.id}")
        return SELECT_ABOUT
    except Exception as e:
        logger.error(f"## Failed to send message: {e}")
    finally:
        logger.debug(f"## update: {update} \n ## context: {context}")


async def back_to_about(update: Update, context: CallbackContext):
    logger.info(f"## back_to_about()")
    query = update.callback_query
    await query.answer()
    keyboard = about_initial_keyboard()
    reply_markup = InlineKeyboardMarkup(keyboard)
    logger.debug(f"## Keyboard created: {keyboard}")
    await query.edit_message_text(
        text="어떤 게 알고 싶어?",
        reply_markup=reply_markup,
    )
    logger.info(f"## Message sent to chat ID: {update.effective_chat.id}")
    return SELECT_ABOUT


async def about_button(update: Update, context):
    logger.info(f"## about_button()")
    query = update.callback_query
    logger.info(f"## Button clicked. Callback data: {query.data}")
    try:
        await query.answer()
        logger.info("## Callback query answered successfully.")
    except Exception as e:
        logger.error(f"## Error in answering callback query: {e}")
    finally:
        logger.debug(f"## update: {update} \n ## context: {context}")
    # Branching based on button selection
    if query.data == "career":
        return await about_career(update, context)
    elif query.data == "go_back":
        return await back_to_about(update, context)
    elif query.data == "cancel":
        return await cancel(update, context)


def format_career_data() -> str:
    logger.info(f"## format_career_data()")
    c = create_cursor(connect_to_oracle(ORA_USER, ORA_PASS, DSN))
    c.execute(
        """
        SELECT start_date, end_date, company_name, company_url, role_title, description
          FROM telegram.user_career
    """
    )
    career_data = c.fetchall()
    message = ""
    for row in career_data:
        message += f"<i><b>{row[0]} → {row[1]}</b></i>\n"  # start_date / end_date
        message += f"<a href='{row[3]}'><u><b>{row[2]}</b></u></a>\n"  # company_url / company_name
        message += f"{row[4]}\n"  # role_title
        message += f"<blockquote>{row[5]}</blockquote>\n"  # description
        message += "\n"
    return message


async def about_career(update: Update, context: CallbackContext):
    logger.info(f"## about_career()")
    query = update.callback_query
    await query.answer()
    keyboard = go_back_keyboard()
    reply_markup = InlineKeyboardMarkup(keyboard)
    logger.debug(f"## Keyboard created: {keyboard}")
    await query.edit_message_text(
        text=format_career_data(),
        reply_markup=reply_markup,
        parse_mode="HTML",
        disable_web_page_preview=True,
    )
    logger.debug(f"## update: {update} \n ## context: {context}")
    return SELECT_ABOUT


async def main():
    commands = [
        BotCommand("start", "마루야, 안녕!"),
        BotCommand("auth", "마루야, 인증할까?"),
        BotCommand("utils", "마루야, 같이 놀까?"),
        BotCommand("about", "마루야, 궁금한 게 있어!"),
    ]

    # Set commands
    await application.bot.set_my_commands(commands)
    logger.info(f"## application.bot.set_my_commands(commands)")

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    logger.info(f"## application.add_handler(CommandHandler('start', start))")

    auth_handler = RedisConversationHandler(
        entry_points=[CommandHandler("auth", auth_start)],
        states={
            WAITING_FOR_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, auth_password),
                CallbackQueryHandler(cancel, pattern="^cancel$"),  # 콜백 핸들러 추가
            ]
        },
        fallbacks=[MessageHandler(filters.COMMAND, cancel)],
    )
    application.add_handler(auth_handler)
    logger.info(f"## application.add_handler(auth_handler)")

    application.add_handler(CommandHandler("utils", utils))
    logger.info(f"## application.add_handler(CommandHandler('utils', utils))")

    utils_handler = RedisConversationHandler(
        entry_points=[CallbackQueryHandler(utils_button)],
        states={
            SELECT_COUNT: [CallbackQueryHandler(input_count)],
            INPUT_COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, save_count)],
            SELECT_NAMING: [CallbackQueryHandler(set_names)],
            INPUT_NAMES: [MessageHandler(filters.TEXT & ~filters.COMMAND, save_names)],
        },
        fallbacks=[],
    )
    application.add_handler(utils_handler)
    logger.info(f"## application.add_handler(utils_handler)")

    about_handler = RedisConversationHandler(
        entry_points=[CommandHandler("about", about)],
        states={
            SELECT_ABOUT: [
                CallbackQueryHandler(about_button),
                MessageHandler(filters.TEXT & ~filters.COMMAND, about_career),
            ],
        },
        fallbacks=[],
    )
    application.add_handler(about_handler)
    logger.info(f"## application.add_handler(about_handler)")

    # Initialize the application
    await application.initialize()
    logger.info(f"## application.initialize()")

    # Run Quart app
    await app.run_task(host="0.0.0.0", port=8000)
    logger.info(f"## app.run_task(host='0.0.0.0', port=8000)")


if __name__ == "__main__":
    # Logging settings
    logging.basicConfig(
        format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
        datefmt="%Y%m%d%H%M%S",
        level=logging.INFO,
    )
    logger = logging.getLogger(__name__)

    asyncio.run(main())
