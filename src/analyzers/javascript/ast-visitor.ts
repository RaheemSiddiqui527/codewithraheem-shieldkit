import { parse, ParserOptions } from '@babel/parser';

export interface ASTVisitorCallbacks {
  enter?: (node: any, parent: any | null) => void;
  leave?: (node: any, parent: any | null) => void;
}

export function parseSourceToAST(code: string, isTypeScript: boolean = true): any | null {
  const plugins: ParserOptions['plugins'] = [
    'jsx',
    'asyncDoExpressions',
    'decimal',
    'decorators-legacy',
    'destructuringPrivate',
    'doExpressions',
    'exportDefaultFrom',
    'functionBind',
    'importAttributes',
    'moduleBlocks',
    'partialApplication',
    'throwExpressions',
    'topLevelAwait',
  ];

  if (isTypeScript) {
    plugins.push('typescript');
  }

  try {
    return parse(code, {
      sourceType: 'unambiguous',
      plugins,
      errorRecovery: true,
      attachComment: false,
    });
  } catch {
    // If TypeScript plugin fails or syntax is malformed, try standard fallback
    try {
      return parse(code, {
        sourceType: 'unambiguous',
        plugins: ['jsx', 'topLevelAwait'],
        errorRecovery: true,
      });
    } catch {
      return null;
    }
  }
}

/**
 * Traverses a Babel AST recursively without external native dependencies.
 */
export function walkAST(
  node: any,
  callbacks: ASTVisitorCallbacks,
  parent: any | null = null,
): void {
  if (!node || typeof node !== 'object') return;

  callbacks.enter?.(node, parent);

  for (const key of Object.keys(node)) {
    if (key === 'parent' || key === 'loc' || key === 'comments') continue;
    const child = node[key];

    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && typeof item.type === 'string') {
          walkAST(item, callbacks, node);
        }
      }
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      walkAST(child, callbacks, node);
    }
  }

  callbacks.leave?.(node, parent);
}
