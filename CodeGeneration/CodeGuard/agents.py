import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

load_dotenv()


def create_llm(model_name):
    return ChatOpenAI(
        model=model_name, temperature=0, api_key=os.getenv("OPENAI_API_KEY")
    )


def create_generator(llm):
    prompt = PromptTemplate(
        input_variables=["task"],
        template="""
You are a secure software engineer.

Write secure code for:
{task}

Follow OWASP best practices.
""",
    )
    return LLMChain(llm=llm, prompt=prompt)


def create_auditor(llm):
    prompt = PromptTemplate(
        input_variables=["code"],
        template="""
Audit this code for vulnerabilities:

{code}

Return issues or SAFE.
""",
    )
    return LLMChain(llm=llm, prompt=prompt)


def create_refiner(llm):
    prompt = PromptTemplate(
        input_variables=["code", "feedback"],
        template="""
Fix the code based on:

{feedback}

Code:
{code}

Return only improved code.
""",
    )
    return LLMChain(llm=llm, prompt=prompt)
