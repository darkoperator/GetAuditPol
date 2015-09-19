// GetAuditPol.cpp : Defines the entry point for the console application.
//

// Target Windows XP SP3 as the minumun. 
#ifndef _WIN32_WINNT 
#define _WIN32_WINNT 0x0501 
#endif 

#include <tchar.h> 
#include <locale.h> 
#include <stdio.h> 

#include <windows.h> 
#include <Ntsecapi.h> 

static void DisplayError(LPCTSTR message);
static void EnumerateCategories(void);
static void EnumerateSubCategories(const GUID *Guid);
static void PrintStatus(const GUID *SubCategoryGuid);

int _tmain()
{
	_tsetlocale(LC_ALL, _T(""));

	EnumerateCategories();

	return 0;
} 

static void DisplayError(LPCTSTR message)
{
	LPTSTR buffer = NULL;
	if (message == NULL)
		message = _T("Error");

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, GetLastError(), 0, (LPTSTR)&buffer, 0, NULL) == 0)
	{
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
			_tprintf(_T("%s : not enough memory\n"), message);
		else
			_tprintf(_T("FormatMessage() failed : %lu\n"), GetLastError());
	}
	else
	{
		_tprintf(_T("%s : %s"), message, buffer);
		LocalFree(buffer);
		buffer = NULL;
	}
}

static void EnumerateCategories(void)
{
	GUID *Tbl;
	DWORD Size;
	BOOL ret;
	DWORD boucle;

	ret = AuditEnumerateCategories(&Tbl, &Size);
	if (ret == FALSE)
	{
		DisplayError(_T("Error AuditEnumerateCategories()"));
		return;
	}

	for (boucle = 0; boucle != Size; boucle++)
	{
		LPTSTR Str;

		/* display category name */
		ret = AuditLookupCategoryName(&Tbl[boucle], &Str);
		if (ret == FALSE)
		{
			DisplayError(_T("Error getting Audit Category Name"));
			return;
		}
		_tprintf(_T("Category = %s\n"), Str);
		AuditFree(Str);

		/* display sub categories */
		EnumerateSubCategories(&Tbl[boucle]);
	}
	AuditFree(Tbl);
}

static void EnumerateSubCategories(const GUID *Guid)
{
	GUID *SubTbl;
	DWORD SubSize;
	DWORD boucle2;
	BOOL ret;
	LPTSTR Str;

	/* get sub categories */
	ret = AuditEnumerateSubCategories(Guid, FALSE, &SubTbl, &SubSize);
	if (ret == FALSE)
	{
		DisplayError(_T("Error AuditEnumerateSubCategories()"));
		return;
	}

	for (boucle2 = 0; boucle2 != SubSize; boucle2++)
	{
		ret = AuditLookupSubCategoryName(&SubTbl[boucle2], &Str);
		if (ret == FALSE)
		{
			DisplayError(_T("Error AuditLookupSubCategoryName()"));
			return;
		}
		_tprintf(L"\t%s", Str);
		AuditFree(Str);

		PrintStatus(&SubTbl[boucle2]);
	}
	AuditFree(SubTbl);
}

static void PrintStatus(const GUID *SubCategoryGuid)
{
	BOOL ret;
	AUDIT_POLICY_INFORMATION *p_information;
	BOOL at_least_one = FALSE;

	ret = AuditQuerySystemPolicy(SubCategoryGuid, 1, &p_information);
	if (ret == FALSE)
	{
		DisplayError(_T("Error AuditQuerySystemPolicy()"));
		return;
	}

	if ((p_information->AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS) == POLICY_AUDIT_EVENT_SUCCESS)
	{
		if (at_least_one == FALSE)
		{
			at_least_one = TRUE;
			_tprintf(_T(" ("));
		}
		else
		{
			_tprintf(_T(", "));
		}
		_tprintf(_T("Success"));
	}

	if ((p_information->AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) == POLICY_AUDIT_EVENT_FAILURE)
	{
		if (at_least_one == FALSE)
		{
			at_least_one = TRUE;
			_tprintf(_T(" ("));
		}
		else
		{
			_tprintf(_T(", "));
		}
		_tprintf(_T("Failure"));
	}

	if ((p_information->AuditingInformation & POLICY_AUDIT_EVENT_NONE) == POLICY_AUDIT_EVENT_NONE)
	{
		if (at_least_one == FALSE)
		{
			at_least_one = TRUE;
			_tprintf(_T(" ("));
		}
		else
		{
			_tprintf(_T(", "));
		}
		_tprintf(_T("None"));
	}

	if (at_least_one == TRUE)
	{
		_tprintf(_T(")"));
	}
	_tprintf(_T("\n"));

	AuditFree(p_information);
}
